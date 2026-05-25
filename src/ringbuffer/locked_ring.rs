use crate::ringbuffer::per_cpu_ring::PerCpuRingBuffer;
use crate::ringbuffer::{LockFreeQueue, NotifyCallback, RecordHeader};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use wdk_sys::{NTSTATUS, PVOID};

enum LockedRingItem {
    Slice(Vec<u8>),
    Record {
        header: RecordHeader,
        data: Vec<u8>,
    },
}

/// A locked ring buffer structure designed for concurrent multi-core access.
///
/// It uses a lock-free `LockFreeQueue` and a CAS-protected drain lock pattern to
/// serialize concurrent writes into a single-producer `PerCpuRingBuffer`. This
/// eliminates any spinlock blocking/spinning and delivers high, deterministic performance.
pub struct LockedRingBuffer {
    inner: Box<PerCpuRingBuffer>,
    queue: LockFreeQueue<LockedRingItem>,
    drain_lock: AtomicBool,
}

unsafe impl Send for LockedRingBuffer {}
unsafe impl Sync for LockedRingBuffer {}

impl LockedRingBuffer {
    /// Allocates and initializes the locked ring buffer.
    pub fn allocate(size: usize) -> Result<Box<Self>, NTSTATUS> {
        let inner = PerCpuRingBuffer::allocate(size, 1)?;
        let queue = LockFreeQueue::new();
        let drain_lock = AtomicBool::new(false);

        Ok(Box::new(Self {
            inner,
            queue,
            drain_lock,
        }))
    }

    /// Registers the callback function to be triggered when new packets arrive.
    pub fn set_notify_callback(&self, cb: Option<NotifyCallback>, ctx: *mut core::ffi::c_void) {
        self.inner.set_notify_callback(cb, ctx);
    }

    /// Marks that the consumer is waiting for packets.
    #[inline(always)]
    pub fn set_watching(&self) {
        self.inner.set_watching();
    }

    /// Clears the watching flag without triggering the callback.
    #[inline(always)]
    pub fn clear_watching(&self) {
        self.inner.clear_watching();
    }

    /// Enqueues a raw slice to the ring buffer.
    pub fn push_slice(&self, data: &[u8]) -> Result<(), NTSTATUS> {
        self.queue.enqueue(LockedRingItem::Slice(data.to_vec()));
        self.drain();
        Ok(())
    }

    /// Enqueues a formatted record (header + data) to the ring buffer.
    pub fn push_record(&self, header: &RecordHeader, data: &[u8]) -> Result<(), NTSTATUS> {
        self.queue.enqueue(LockedRingItem::Record {
            header: *header,
            data: data.to_vec(),
        });
        self.drain();
        Ok(())
    }

    /// Maps both the header and data memory regions to user space.
    pub fn map_to_user_space(&self) -> Result<(PVOID, PVOID), NTSTATUS> {
        self.inner.map_to_user_space()
    }

    /// Highly optimized lock-free queue draining helper using CAS.
    fn drain(&self) {
        // Attempt to acquire the drain lock. If already acquired, return immediately.
        // The current holder of the lock will process the item we just enqueued.
        if self.drain_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        loop {
            // Process all items currently in the queue
            while let Some(item) = self.queue.dequeue() {
                match item {
                    LockedRingItem::Slice(data) => {
                        let _ = self.inner.transaction(0, data.len(), |tx| {
                            tx.push_slice_only(&data);
                            Ok(())
                        });
                    }
                    LockedRingItem::Record { header, data } => {
                        let expected_total_size = core::mem::size_of::<RecordHeader>() + data.len();
                        let _ = self.inner.transaction(0, expected_total_size, |tx| {
                            tx.push_slice(&header, &data)
                        });
                    }
                }
            }

            // Release the drain lock
            self.drain_lock.store(false, Ordering::Release);

            // Double check: if more items were enqueued after we released the lock,
            // we must re-acquire and continue draining to prevent packet freezing.
            if self.queue.is_empty() {
                break;
            }

            if self.drain_lock
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                // Someone else acquired it, they will drain any new items.
                break;
            }
        }
    }
}
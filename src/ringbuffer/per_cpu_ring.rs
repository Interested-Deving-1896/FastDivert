/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::log;
use crate::ringbuffer::data::RingBufferData;
use crate::ringbuffer::mm::{KernelMemory, ReservedKernelMemory};
use crate::ringbuffer::{map_to_userspace, NotifyCallback, RecordHeader, RingBufferHeader};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};
use wdk::wdf::SpinLock;
use wdk_sys::{
    NTSTATUS, PMDL, PVOID, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_STATE, ULONG,
};

/// Represents an ongoing write operation to the ring buffer.
///
/// Ensures that data is only committed (and the consumer notified) if the entire
/// sequence of pushes succeeds.
pub struct RingBufferTransaction<'a> {
    rb: &'a PerCpuRingBuffer,
    core_index: u32,
    pub(crate) start_tail: usize,
    offset: usize,
}

impl<'a> RingBufferTransaction<'a> {
    /// Pushes a header and a byte slice into the ring buffer sequentially.
    pub fn push_slice(&mut self, header: &RecordHeader, data: &[u8]) -> Result<(), NTSTATUS> {
        let rb = self.rb.get_ring_buffer(self.core_index);

        let header_slice = unsafe {
            core::slice::from_raw_parts(
                header as *const _ as *const u8,
                core::mem::size_of::<RecordHeader>(),
            )
        };

        rb.push_slice_at(self.start_tail, header_slice, self.offset);
        rb.push_slice_at(self.start_tail, data, self.offset + header_slice.len());

        self.offset += header_slice.len() + data.len();
        Ok(())
    }

    /// Pushes a header and data directly from an MDL into the ring buffer.
    pub fn push_mdl(
        &mut self,
        header: &RecordHeader,
        mdl: PMDL,
        mdl_offset: usize,
        length: usize,
    ) -> Result<(), NTSTATUS> {
        let rb = self.rb.get_ring_buffer(self.core_index);

        let header_slice = unsafe {
            core::slice::from_raw_parts(
                header as *const _ as *const u8,
                core::mem::size_of::<RecordHeader>(),
            )
        };

        rb.push_slice_at(self.start_tail, header_slice, self.offset);
        rb.push_mdl_at(self.start_tail, mdl, mdl_offset, length, self.offset + header_slice.len())?;

        self.offset += header_slice.len() + length;
        Ok(())
    }

    /// Pushes data directly from an MDL into the ring buffer without a header.
    pub fn push_mdl_only(
        &mut self,
        mdl: PMDL,
        mdl_offset: usize,
        length: usize,
    ) -> Result<(), NTSTATUS> {
        let rb = self.rb.get_ring_buffer(self.core_index);
        rb.push_mdl_at(self.start_tail, mdl, mdl_offset, length, self.offset)?;
        self.offset += length;
        Ok(())
    }

    /// Pushes a byte slice into the ring buffer without a header.
    pub fn push_slice_only(&mut self, data: &[u8]) {
        let rb = self.rb.get_ring_buffer(self.core_index);
        rb.push_slice_at(self.start_tail, data, self.offset);
        self.offset += data.len();
    }

    /// Returns the raw virtual address and the contiguous size available for writing at the current offset.
    /// If the write wraps around, it returns the first part and the second part.
    pub fn get_write_ptrs(&self, len: usize) -> (*mut u8, usize, *mut u8, usize) {
        let rb = self.rb.get_ring_buffer(self.core_index);
        let write_offset = (self.start_tail + self.offset) & rb.mask();
        let len1 = (rb.size() - write_offset).min(len);
        let len2 = len - len1;

        let ptr1 = unsafe { rb.addr_virtual().add(write_offset) };
        let ptr2 = if len2 > 0 { rb.addr_virtual() } else { core::ptr::null_mut() };

        (ptr1, len1, ptr2, len2)
    }

    /// Advances the offset after a custom write.
    pub fn advance_offset(&mut self, len: usize) {
        self.offset += len;
    }
}

/// A ring buffer structure designed for concurrent multi-core access.
///
/// Internally, it allocates an array of individual ring buffers, one for each processor core,
/// to avoid lock contention during high-throughput packet processing.
pub struct PerCpuRingBuffer {
    /// Array of ring buffer data structures, one per core.
    /// Dropped first to ensure memory references are stopped before unmapping.
    rb_datas: Vec<RingBufferData>,

    /// Reserved memory mapping for the actual buffer data.
    data_mem: ReservedKernelMemory,
    /// Standard memory mapping for the buffer headers (head/tail pointers).
    header_mem: KernelMemory,

    /// Number of active processor cores / ring buffers.
    workers_num: u32,

    /// Flag to track if user-mode is currently waiting for data (pending RECV IRP).
    is_watching: AtomicBool,

    /// Callback to execute when data is written and user-mode is watching.
    notify_lock: SpinLock,
    notify_cb: Option<NotifyCallback>,
    /// Context passed to the notify callback (usually the WDFREQUEST pointer).
    notify_ctx: *mut core::ffi::c_void,
}

unsafe impl Send for PerCpuRingBuffer {}
unsafe impl Sync for PerCpuRingBuffer {}

impl PerCpuRingBuffer {
    /// Allocates and initializes the per-CPU ring buffers.
    ///
    /// The `size` must be a power of 2. If `workers_num` is 0, it defaults to the
    /// active processor count of the system.
    pub fn allocate(size: usize, mut workers_num: ULONG) -> Result<Box<Self>, NTSTATUS> {
        if size == 0 || (size & (size - 1)) != 0 {
            log!("PerCpuRingBuffer: Invalid ring buffer size: {}", size);
            return Err(STATUS_INVALID_DEVICE_STATE);
        }

        if workers_num == 0 {
            workers_num = unsafe {
                wdk_sys::ntddk::KeQueryActiveProcessorCountEx(
                    wdk_sys::ALL_PROCESSOR_GROUPS as wdk_sys::USHORT,
                ) as wdk_sys::ULONG
            };
        }

        if workers_num == 0 {
            log!("PerCpuRingBuffer: Failed to get active processor count");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }

        // Allocate memory for the ring buffer headers
        let header_total_size = size_of::<RingBufferHeader>() * (workers_num as usize);
        let header_mem =
            KernelMemory::allocate(header_total_size).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;

        unsafe {
            core::ptr::write_bytes(header_mem.va as *mut u8, 0, header_total_size);
        }

        // Allocate memory for the ring buffer data payload
        let data_total_size = size * (workers_num as usize);
        let data_mem =
            ReservedKernelMemory::allocate(data_total_size).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let rb_data_va = data_mem.va;

        unsafe {
            core::ptr::write_bytes(rb_data_va as *mut u8, 0, data_total_size);
        }

        // Initialize individual ring buffers
        let mut ring_buffer_data: Vec<RingBufferData> = Vec::with_capacity(workers_num as usize);

        for core in 0..workers_num {
            unsafe {
                let data_ptr = (rb_data_va as *mut u8).add(core as usize * size);
                let header_ptr = (header_mem.va as *mut RingBufferHeader).add(core as usize);

                // If workers_num is <= 1, the only queue (index 0) must be a CAS queue.
                // Otherwise, the last queue (index workers_num - 1) is a CAS queue,
                // and all preceding queues (0..workers_num - 1) are SPSC queues.
                let is_cas = if workers_num <= 1 {
                    true
                } else {
                    core == workers_num - 1
                };

                let rb = RingBufferData::new(size, header_ptr, data_ptr, is_cas)
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
                ring_buffer_data.push(rb);
            }
        }

        let notify_lock = SpinLock::create(&mut wdk_sys::WDF_OBJECT_ATTRIBUTES {
            Size: size_of::<wdk_sys::WDF_OBJECT_ATTRIBUTES>() as ULONG,
            ExecutionLevel: wdk_sys::_WDF_EXECUTION_LEVEL::WdfExecutionLevelInheritFromParent,
            SynchronizationScope:
                wdk_sys::_WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeInheritFromParent,
            ..Default::default()
        })?;

        Ok(Box::new(Self {
            data_mem,
            header_mem,
            workers_num,
            rb_datas: ring_buffer_data,
            is_watching: AtomicBool::new(false),
            notify_lock,
            notify_cb: None,
            notify_ctx: null_mut(),
        }))
    }

    /// Registers the callback function to be triggered when new packets arrive.
    pub fn set_notify_callback(&self, cb: Option<NotifyCallback>, ctx: *mut core::ffi::c_void) {
        unsafe {
            self.notify_lock.acquire();
            let self_ptr = self as *const _ as *mut Self;
            (*self_ptr).notify_cb = cb;
            (*self_ptr).notify_ctx = ctx;
            self.notify_lock.release();
        }
    }

    /// Marks that the consumer is waiting for packets.
    #[inline(always)]
    pub fn set_watching(&self) {
        self.is_watching.store(true, Ordering::Release);
    }

    /// Clears the watching flag without triggering the callback.
    #[inline(always)]
    pub fn clear_watching(&self) {
        self.is_watching.store(false, Ordering::Release);
    }

    /// Atomically clears the watching flag.
    ///
    /// Returns `true` if we cleared it (i.e., nobody else already fired the notify callback),
    /// `false` if a callout already cleared it first.
    #[inline(always)]
    pub fn test_and_clear_watching_flag(&self) -> bool {
        self.is_watching.swap(false, Ordering::AcqRel)
    }

    /// Retrieves the internal ring buffer structure for a specific core.
    ///
    /// Implements dynamic routing for CPU hotplugging/overflow:
    /// - Cores `< workers_num - 1` are routed to their dedicated SPSC queue.
    /// - Cores `>= workers_num - 1` are routed to the shared CAS MPSC queue (the last queue).
    pub(crate) fn get_ring_buffer(&self, core: u32) -> &RingBufferData {
        if self.workers_num <= 1 {
            &self.rb_datas[0]
        } else if core < self.workers_num - 1 {
            &self.rb_datas[core as usize]
        } else {
            &self.rb_datas[self.workers_num as usize - 1]
        }
    }

    pub fn get_ring_buffer_size(&self) -> usize {
        self.rb_datas[0].get_size()
    }

    /// Checks if there are unread packets across all cores.
    pub fn has_unread_packets(&self) -> bool {
        for i in 0..self.workers_num {
            let rb = self.get_ring_buffer(i);
            if rb.has_unread() {
                return true;
            }
        }
        false
    }

    /// Checks if a specific core's ring buffer has unread packets.
    pub fn has_unread(&self, core: u32) -> bool {
        self.get_ring_buffer(core).has_unread()
    }

    /// Reads data from the ring buffer into the destination slice.
    pub fn pop_slice(&self, core: u32, dest: &mut [u8], offset_from_head: usize) -> Result<(), ()> {
        self.get_ring_buffer(core).pop_slice(dest, offset_from_head)
    }

    /// Advances the consumer head pointer, effectively consuming the read packets.
    pub fn add_head(&self, core: u32, delta: usize) {
        self.get_ring_buffer(core).add_head(delta)
    }

    /// Starts a transaction to write into the ring buffer.
    ///
    /// Provides the expected total size to check for available space and atomically reserve it.
    /// If the closure returns `Ok`, the tail pointer is committed and the consumer is notified.
    /// Under CAS mode, if the closure fails or returns `Err`, a fail-safe dummy record is committed
    /// to prevent deadlocking subsequent producers in the CAS queue.
    pub fn transaction<F, R>(
        &self,
        core_index: u32,
        expected_total_size: usize,
        f: F,
    ) -> Result<R, NTSTATUS>
    where
        F: FnOnce(&mut RingBufferTransaction) -> Result<R, NTSTATUS>,
    {
        let rb = self.get_ring_buffer(core_index);

        // Atomically reserve space and get the unique start_tail
        let start_tail = rb.reserve_space(expected_total_size)?;

        let mut tx = RingBufferTransaction {
            rb: self,
            core_index,
            start_tail,
            offset: 0,
        };

        match f(&mut tx) {
            Ok(res) => {
                if tx.offset > 0 {
                    // Commit the actually written bytes
                    rb.commit_tail(start_tail, tx.offset);

                    // Under high load, we MUST ensure that the queue is poked if there are packets.
                    // We use is_watching to avoid redundant DPC/callback overhead.
                    // If it was true, we set it to false and fire the callback.
                    if self.is_watching.swap(false, Ordering::Acquire) {
                        let (cb, ctx) = unsafe {
                            self.notify_lock.acquire();
                            let cb = self.notify_cb;
                            let ctx = self.notify_ctx;
                            self.notify_lock.release();
                            (cb, ctx)
                        };

                        if let Some(cb) = cb {
                            unsafe { cb(ctx) };
                        }
                    }
                } else if rb.is_cas() {
                    // Fail-safe under CAS: even if offset is 0, we reserved space, so we must
                    // write a dummy record and commit expected_total_size to avoid deadlocking subsequent threads.
                    let dummy_header = RecordHeader {
                        len: (expected_total_size - core::mem::size_of::<RecordHeader>()) as u32,
                        _reserved: 0xDEADBEEF,
                    };
                    let dummy_slice = unsafe {
                        core::slice::from_raw_parts(
                            &dummy_header as *const _ as *const u8,
                            core::mem::size_of::<RecordHeader>(),
                        )
                    };
                    rb.push_slice_at(start_tail, dummy_slice, 0);
                    rb.commit_tail(start_tail, expected_total_size);
                }
                Ok(res)
            }
            Err(e) => {
                if rb.is_cas() {
                    // Fail-safe under CAS: write a dummy record and commit expected_total_size
                    // to avoid deadlocking subsequent threads.
                    let dummy_header = RecordHeader {
                        len: (expected_total_size - core::mem::size_of::<RecordHeader>()) as u32,
                        _reserved: 0xDEADBEEF,
                    };
                    let dummy_slice = unsafe {
                        core::slice::from_raw_parts(
                            &dummy_header as *const _ as *const u8,
                            core::mem::size_of::<RecordHeader>(),
                        )
                    };
                    rb.push_slice_at(start_tail, dummy_slice, 0);
                    rb.commit_tail(start_tail, expected_total_size);
                }
                Err(e)
            }
        }
    }

    /// Maps both the header and data memory regions to user space.
    ///
    /// Must be called at PASSIVE_LEVEL IRQL.
    pub fn map_to_user_space(&self) -> Result<(PVOID, PVOID), NTSTATUS> {
        let irql = unsafe { wdk_sys::ntddk::KeGetCurrentIrql() };
        if irql != wdk_sys::PASSIVE_LEVEL as u8 {
            log!(
                "PerCpuRingBuffer: map_to_user_space called at invalid IRQL: {}",
                irql
            );
            return Err(STATUS_INVALID_DEVICE_STATE);
        }

        let header_va = map_to_userspace(self.header_mem.mdl())?;
        let data_va = map_to_userspace(self.data_mem.mdl())?;

        Ok((header_va, data_va))
    }

    pub fn workers_num(&self) -> u32 {
        self.workers_num
    }
}
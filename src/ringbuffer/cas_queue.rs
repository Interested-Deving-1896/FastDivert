use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

struct Node<T> {
    value: Option<T>,
    next: AtomicPtr<Node<T>>,
}

/// A thread-safe, lock-free Michael-Scott FIFO Queue using atomic pointers.
pub struct LockFreeQueue<T> {
    head: AtomicPtr<Node<T>>,
    tail: AtomicPtr<Node<T>>,
}

unsafe impl<T: Send> Send for LockFreeQueue<T> {}
unsafe impl<T: Send> Sync for LockFreeQueue<T> {}

impl<T> LockFreeQueue<T> {
    /// Creates a new, empty LockFreeQueue.
    pub fn new() -> Self {
        let sentinel = Box::into_raw(Box::new(Node {
            value: None,
            next: AtomicPtr::new(ptr::null_mut()),
        }));
        Self {
            head: AtomicPtr::new(sentinel),
            tail: AtomicPtr::new(sentinel),
        }
    }

    /// Enqueues an item at the tail of the queue.
    pub fn enqueue(&self, val: T) {
        let new_node = Box::into_raw(Box::new(Node {
            value: Some(val),
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*tail).next.load(Ordering::Acquire) };

            if tail == self.tail.load(Ordering::Relaxed) {
                if next.is_null() {
                    // Try to link the new node to the end of the list
                    if unsafe {
                        (*tail)
                            .next
                            .compare_exchange(
                                ptr::null_mut(),
                                new_node,
                                Ordering::Release,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                    } {
                        // Successfully linked! Try to swing tail to the new node
                        let _ = self.tail.compare_exchange(
                            tail,
                            new_node,
                            Ordering::Release,
                            Ordering::Relaxed,
                        );
                        return;
                    }
                } else {
                    // Tail was lagging, try to swing it to the next node
                    let _ = self.tail.compare_exchange(
                        tail,
                        next,
                        Ordering::Release,
                        Ordering::Relaxed,
                    );
                }
            }
        }
    }

    /// Dequeues an item from the head of the queue.
    pub fn dequeue(&self) -> Option<T> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*head).next.load(Ordering::Acquire) };

            if head == self.head.load(Ordering::Relaxed) {
                if head == tail {
                    if next.is_null() {
                        return None; // Queue is empty
                    }
                    // Tail is lagging, swing tail forward
                    let _ = self.tail.compare_exchange(
                        tail,
                        next,
                        Ordering::Release,
                        Ordering::Relaxed,
                    );
                } else {
                    // Swing head to next node
                    if self.head
                        .compare_exchange(head, next, Ordering::Release, Ordering::Relaxed)
                        .is_ok()
                    {
                        // This thread won the race. We can safely extract the value from next.
                        let val = unsafe { (*next).value.take() };
                        // Deallocate the old sentinel node (head)
                        let _ = unsafe { Box::from_raw(head) };
                        return val;
                    }
                }
            }
        }
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let next = unsafe { (*head).next.load(Ordering::Acquire) };
        next.is_null()
    }
}

impl<T> Drop for LockFreeQueue<T> {
    fn drop(&mut self) {
        while self.dequeue().is_some() {}
        let head = self.head.load(Ordering::Relaxed);
        if !head.is_null() {
            let _ = unsafe { Box::from_raw(head) };
        }
    }
}

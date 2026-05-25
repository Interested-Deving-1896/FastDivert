use crate::ringbuffer::RingBufferHeader;
use core::sync::atomic::{AtomicUsize, Ordering};
use wdk_sys::{NTSTATUS, PMDL, STATUS_INSUFFICIENT_RESOURCES, ULONG};

pub struct RingBufferData {
    size: usize,
    mask: usize, // size - 1 for quick mod
    header: *mut RingBufferHeader,
    addr_virtual: *mut u8,
    is_cas: bool,
    reserved_tail: AtomicUsize,
}

impl RingBufferData {
    pub fn new(size: usize, header: *mut RingBufferHeader, data: *mut u8, is_cas: bool) -> Option<Self> {
        if size == 0 || (size & (size - 1)) != 0 {
            return None;
        }

        unsafe {
            (*header).c.head = AtomicUsize::new(0);
            (*header).p.tail = AtomicUsize::new(0);

            Some(RingBufferData {
                size,
                mask: size - 1,
                header,
                addr_virtual: data,
                is_cas,
                reserved_tail: AtomicUsize::new(0),
            })
        }
    }

    #[inline(always)]
    pub fn is_cas(&self) -> bool {
        self.is_cas
    }

    #[inline(always)]
    pub fn mask(&self) -> usize {
        self.mask
    }

    #[inline(always)]
    pub fn size(&self) -> usize {
        self.size
    }

    #[inline(always)]
    pub fn addr_virtual(&self) -> *mut u8 {
        self.addr_virtual
    }

    /// Atomically reserve space for writing in SPSC or CAS MPSC mode.
    ///
    /// - For SPSC: Simply checks free space against `free_space()` and returns current tail.
    /// - For CAS MPSC: Atomically advances `reserved_tail` using a spin-CAS loop, verifying
    ///   that the space is not already wrapped-around and occupied by the unread head.
    pub fn reserve_space(&self, expected_total_size: usize) -> Result<usize, NTSTATUS> {
        if !self.is_cas {
            // SPSC Path: No concurrent writers, just check free space
            if !self.check_free_space(expected_total_size) {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            return Ok(self.get_tail());
        }

        // CAS MPSC Path:
        loop {
            let current_reserved = self.reserved_tail.load(Ordering::Acquire);
            let head = self.get_head();

            // Calculate active unread size based on already-reserved space
            let reserved_unread = current_reserved.wrapping_sub(head);
            if self.size - reserved_unread < expected_total_size {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }

            let new_reserved = current_reserved.wrapping_add(expected_total_size);
            match self.reserved_tail.compare_exchange_weak(
                current_reserved,
                new_reserved,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(current_reserved);
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Commits the tail pointer of the ring buffer, making the written data visible to the consumer.
    ///
    /// - For SPSC: Directly advances the tail pointer.
    /// - For CAS MPSC: Spins/yields using a spin-CAS loop until `tail == start_tail`
    ///   (ensuring ordered commit of reservations), then atomically updates the tail to `start_tail + size`.
    pub fn commit_tail(&self, start_tail: usize, expected_total_size: usize) {
        if !self.is_cas {
            // SPSC Path: Direct tail commit
            self.set_tail(start_tail.wrapping_add(expected_total_size));
            return;
        }

        // CAS MPSC Path: Ordered tail commit
        let target_tail = start_tail.wrapping_add(expected_total_size);
        loop {
            match unsafe {
                (*self.header).p.tail.compare_exchange_weak(
                    start_tail,
                    target_tail,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
            } {
                Ok(_) => {
                    break;
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    #[inline(always)]
    fn get_head(&self) -> usize {
        unsafe { (*self.header).c.head.load(Ordering::Acquire) }
    }

    #[inline(always)]
    fn get_tail(&self) -> usize {
        unsafe { (*self.header).p.tail.load(Ordering::Acquire) }
    }

    #[inline(always)]
    fn set_tail(&self, tail: usize) {
        unsafe { (*self.header).p.tail.store(tail, Ordering::Release) }
    }

    pub fn add_tail(&self, delta: usize) {
        unsafe {
            let tail = self.get_tail();
            self.set_tail(tail.wrapping_add(delta));
        }
    }

    #[inline(always)]
    fn set_head(&self, head: usize) {
        unsafe { (*self.header).c.head.store(head, Ordering::Release) }
    }

    pub fn add_head(&self, delta: usize) {
        let head = self.get_head();
        self.set_head(head.wrapping_add(delta));
    }

    #[inline(always)]
    pub fn has_unread(&self) -> bool {
        self.get_tail() > self.get_head()
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    #[inline(always)]
    pub fn unread_size(&self) -> usize {
        let head = self.get_head();
        let tail = self.get_tail();
        tail.wrapping_sub(head)
    }

    #[inline(always)]
    pub fn free_space(&self) -> usize {
        self.size - self.unread_size()
    }

    pub fn pop_slice(&self, dest: &mut [u8], offset_from_head: usize) -> Result<(), ()> {
        let data_len = dest.len();
        if self.unread_size() < data_len + offset_from_head {
            return Err(());
        }

        unsafe {
            let head = self.get_head();
            let read_offset = (head + offset_from_head) & self.mask;

            let len1 = (self.size - read_offset).min(data_len);
            let len2 = data_len - len1;

            let src_ptr1 = self.addr_virtual.add(read_offset);
            core::ptr::copy_nonoverlapping(src_ptr1, dest.as_mut_ptr(), len1);

            if len2 > 0 {
                let src_ptr2 = self.addr_virtual;
                core::ptr::copy_nonoverlapping(src_ptr2, dest.as_mut_ptr().add(len1), len2);
            }
        }
        Ok(())
    }

    pub fn check_free_space(&self, data_len: usize) -> bool {
        self.free_space() >= data_len
    }

    /// Pushes data directly from an MDL chain into the ring buffer at the pre-reserved `start_tail` offset.
    pub fn push_mdl_at(
        &self,
        start_tail: usize,
        mut mdl: PMDL,
        mut offset_mdl: usize,
        mut length: usize,
        offset_from_start: usize,
    ) -> Result<usize, NTSTATUS> {
        if length == 0 {
            return Ok(0);
        }

        let mut bytes_copied = 0;

        while length > 0 && !mdl.is_null() {
            let mdl_byte_count = unsafe { (*mdl).ByteCount as usize };
            if mdl_byte_count <= offset_mdl {
                // Move to the next MDL in the chain
                offset_mdl -= mdl_byte_count;
                mdl = unsafe { (*mdl).Next };
                continue;
            }

            let src_addr = crate::wdk_ext::ntddk::MmGetSystemAddressForMdlSafe(
                mdl,
                wdk_sys::_MM_PAGE_PRIORITY::HighPagePriority as ULONG,
            );
            if src_addr.is_null() {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }

            let available_in_mdl = mdl_byte_count - offset_mdl;
            let copy_len = available_in_mdl.min(length);

            let slice = unsafe {
                core::slice::from_raw_parts((src_addr as *const u8).add(offset_mdl), copy_len)
            };
            self.push_slice_at(start_tail, slice, offset_from_start + bytes_copied);

            bytes_copied += copy_len;
            length -= copy_len;

            offset_mdl = 0; // offset of next mdl must be 0
            mdl = unsafe { (*mdl).Next };
        }

        Ok(bytes_copied)
    }

    /// Pushes a byte slice into the ring buffer at the pre-reserved `start_tail` offset.
    pub fn push_slice_at(&self, start_tail: usize, data: &[u8], offset_from_start: usize) -> usize {
        let data_len = data.len();

        unsafe {
            let write_offset = (start_tail + offset_from_start) & self.mask;

            let len1 = (self.size - write_offset).min(data_len);
            let len2 = data_len - len1;

            // First part
            let dest_ptr1 = self.addr_virtual.add(write_offset);
            core::ptr::copy_nonoverlapping(data.as_ptr(), dest_ptr1, len1);

            if len2 > 0 {
                // Second part (wrapped around)
                let dest_ptr2 = self.addr_virtual; // Start of buffer
                core::ptr::copy_nonoverlapping(data.as_ptr().add(len1), dest_ptr2, len2);
            }
        }
        data_len
    }

    /// Read a Sized type from the ring buffer, handling wrap-around boundaries.
    pub fn read_from_rb<T: Copy>(&self, start_tail: usize, offset_from_start: usize) -> T {
        let size = core::mem::size_of::<T>();
        let mut temp = core::mem::MaybeUninit::<T>::uninit();
        unsafe {
            let read_offset = (start_tail + offset_from_start) & self.mask;
            let len1 = (self.size - read_offset).min(size);
            let len2 = size - len1;

            let src_ptr1 = self.addr_virtual.add(read_offset);
            core::ptr::copy_nonoverlapping(src_ptr1, temp.as_mut_ptr() as *mut u8, len1);

            if len2 > 0 {
                let src_ptr2 = self.addr_virtual;
                core::ptr::copy_nonoverlapping(src_ptr2, (temp.as_mut_ptr() as *mut u8).add(len1), len2);
            }
            temp.assume_init()
        }
    }
}

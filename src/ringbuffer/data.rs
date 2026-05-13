/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::ringbuffer::RingBufferHeader;
use core::sync::atomic::{AtomicUsize, Ordering};
use wdk_sys::{NTSTATUS, PMDL, STATUS_INSUFFICIENT_RESOURCES, ULONG};

pub struct RingBufferData {
    size: usize,
    mask: usize, // size -1 for quick mod
    header: *mut RingBufferHeader,
    addr_virtual: *mut u8,
}

impl RingBufferData {
    pub fn new(size: usize, header: *mut RingBufferHeader, data: *mut u8) -> Option<Self> {
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
            })
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

    pub fn push_mdl(
        &self,
        mut mdl: PMDL,
        mut offset_mdl: usize,
        mut length: usize,
        offset_rb_tail: usize,
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
            self.push_slice_no_check(slice, offset_rb_tail + bytes_copied);

            bytes_copied += copy_len;
            length -= copy_len;

            offset_mdl = 0; // offset of next mdl must be 0
            mdl = unsafe { (*mdl).Next };
        }

        Ok(bytes_copied)
    }

    pub fn push_slice_no_check(&self, data: &[u8], offset_from_tail: usize) -> usize {
        let data_len = data.len();

        unsafe {
            let tail = self.get_tail();
            let write_offset = (tail + offset_from_tail) & self.mask;

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
}

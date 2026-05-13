/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

mod data;
mod per_cpu_ring;
mod mm;

use crate::wdk_ext::ndis::*;
use core::ptr::null_mut;
use core::sync::atomic::AtomicUsize;
use wdk_sys::{NTSTATUS, PMDL, PVOID, STATUS_INSUFFICIENT_RESOURCES, ULONG};

pub use per_cpu_ring::PerCpuRingBuffer;

#[repr(C, align(64))]
pub struct ProducerHeader {
    tail: AtomicUsize,
}

#[repr(C, align(64))]
pub struct ConsumerHeader {
    head: AtomicUsize,
}

#[repr(C, align(64))]
pub struct RingBufferHeader {
    pub p: ProducerHeader,
    pub c: ConsumerHeader,
}

#[repr(C)]
pub struct RecordHeader {
    pub len: u32,
    pub ty: u32,
}

#[repr(u32)]
pub enum RecordType {
    Invalid = 0,
    PacketData = 1,
    Address = 2,
}

// Define the type for the callback function
pub type NotifyCallback = unsafe extern "C" fn(*mut core::ffi::c_void);

pub fn map_to_userspace(mdl: PMDL) -> Result<PVOID, NTSTATUS> {
    let user_address = unsafe {
        wdk_sys::ntddk::MmMapLockedPagesSpecifyCache(
            mdl,
            wdk_sys::_MODE::UserMode as i8,
            wdk_sys::_MEMORY_CACHING_TYPE::MmCached,
            null_mut(),
            0,
            wdk_sys::_MM_PAGE_PRIORITY::NormalPagePriority as u32,
        )
    };
    if user_address.is_null() {
        Err(STATUS_INSUFFICIENT_RESOURCES)
    } else {
        Ok(user_address)
    }
}

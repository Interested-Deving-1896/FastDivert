/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::log;
use crate::MEMORY_POOL_TAG;
use core::ptr::null_mut;
use wdk_sys::ntddk::{
    IoFreeMdl, MmAllocateMappingAddress, MmAllocatePagesForMdl, MmFreeMappingAddress,
    MmFreePagesFromMdl, MmMapLockedPagesSpecifyCache, MmMapLockedPagesWithReservedMapping,
    MmUnmapLockedPages, MmUnmapReservedMapping,
};
use wdk_sys::{PMDL, PVOID};

/// Private helper: RAII wrapper for an MDL (Memory Descriptor List).
///
/// Ensures that pages are freed and the MDL is properly destroyed when it goes out of scope.
pub struct MdlGuard(pub PMDL);

impl MdlGuard {
    /// Allocates an MDL for the specified size.
    pub fn allocate(size: usize) -> Option<Self> {
        let mdl = unsafe {
            MmAllocatePagesForMdl(
                wdk_sys::PHYSICAL_ADDRESS { QuadPart: 0 },
                wdk_sys::PHYSICAL_ADDRESS { QuadPart: -1 },
                wdk_sys::PHYSICAL_ADDRESS { QuadPart: 0 },
                size as u64,
            )
        };

        if mdl.is_null() {
            log!("MdlGuard: Failed to allocate MDL of size {}", size);
            None
        } else {
            Some(Self(mdl))
        }
    }
}

impl Drop for MdlGuard {
    fn drop(&mut self) {
        unsafe {
            MmFreePagesFromMdl(self.0);
            IoFreeMdl(self.0);
        }
    }
}

/// Represents standard Kernel Space memory mapping (MDL + MmMapLockedPages).
///
/// Automatically unmaps and releases the memory when dropped.
pub struct KernelMemory {
    pub va: PVOID,
    mdl: MdlGuard,
}

impl KernelMemory {
    /// Allocates and maps memory into Kernel Space.
    pub fn allocate(size: usize) -> Option<Self> {
        let mdl = MdlGuard::allocate(size)?;

        let va = unsafe {
            MmMapLockedPagesSpecifyCache(
                mdl.0,
                wdk_sys::_MODE::KernelMode as i8,
                wdk_sys::_MEMORY_CACHING_TYPE::MmCached,
                null_mut(),
                0,
                wdk_sys::_MM_PAGE_PRIORITY::NormalPagePriority as u32,
            )
        };

        if va.is_null() {
            log!("KernelMemory: Failed to map locked pages");
            None
        } else {
            Some(Self { va, mdl })
        }
    }

    /// Returns the underlying PMDL.
    pub fn mdl(&self) -> PMDL {
        self.mdl.0
    }
}

impl Drop for KernelMemory {
    fn drop(&mut self) {
        if !self.va.is_null() {
            unsafe {
                MmUnmapLockedPages(self.va, self.mdl.0);
            }
        }
    }
}

/// Represents reserved Kernel Space memory mapping (MDL + MmAllocateMappingAddress).
///
/// Useful for scenarios where mapping address must be reserved beforehand.
pub struct ReservedKernelMemory {
    pub va: PVOID,
    mdl: MdlGuard,
}

impl ReservedKernelMemory {
    /// Allocates and reserves memory mapping into Kernel Space.
    pub fn allocate(size: usize) -> Option<Self> {
        let mdl = MdlGuard::allocate(size)?;

        let va = unsafe { MmAllocateMappingAddress(size as wdk_sys::SIZE_T, MEMORY_POOL_TAG) };
        if va.is_null() {
            log!("ReservedKernelMemory: Failed to allocate mapping address");
            return None;
        }

        let view = unsafe {
            MmMapLockedPagesWithReservedMapping(
                va,
                MEMORY_POOL_TAG,
                mdl.0,
                wdk_sys::_MEMORY_CACHING_TYPE::MmCached,
            )
        };

        if view.is_null() {
            log!("ReservedKernelMemory: Failed to map pages with reserved mapping");
            unsafe {
                MmFreeMappingAddress(va, MEMORY_POOL_TAG);
            }
            None
        } else {
            Some(Self { va, mdl })
        }
    }

    /// Returns the underlying PMDL.
    pub fn mdl(&self) -> PMDL {
        self.mdl.0
    }
}

impl Drop for ReservedKernelMemory {
    fn drop(&mut self) {
        if !self.va.is_null() {
            unsafe {
                MmUnmapReservedMapping(self.va, MEMORY_POOL_TAG, self.mdl.0);
                MmFreeMappingAddress(self.va, MEMORY_POOL_TAG);
            }
        }
    }
}

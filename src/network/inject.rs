/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::log;
use crate::wdk_ext::ndis::{
    FwpsAllocateNetBufferAndNetBufferList0, FwpsFreeNetBufferList0, NET_BUFFER_CURRENT_MDL,
    NET_BUFFER_LIST_FIRST_NB,
};
use crate::wdk_ext::ndis::{
    FwpsInjectNetworkReceiveAsync0, FwpsInjectNetworkSendAsync0, NET_BUFFER_LIST,
};
use crate::wdk_ext::ndis::{COMPARTMENT_ID, FWPS_INJECT_COMPLETE0};
use crate::wdk_ext::ntddk::MmGetSystemAddressForMdlSafe;
use core::ptr::null_mut;
use wdk::println;
use wdk_sys::ntddk::{ExFreePoolWithTag, IoFreeMdl, MmUnlockPages};
use wdk_sys::{
    BOOLEAN, PMDL, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, _MM_PAGE_PRIORITY, WDFREQUEST,
};

use crate::wdk_ext::wdf_wrapper::WdfRequestComplete;

/// Context for user-mode injection completion.
#[repr(C)]
pub struct UserInjectionCompletionContext {
    pub mdl: PMDL,
    pub request: WDFREQUEST,
}

/// Callback function when WFP injection is complete, used to free the NBL and related resources (kernel-allocated buffers)
pub unsafe extern "C" fn injection_completion_fn(
    _context: *mut core::ffi::c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: BOOLEAN,
) {
    if !net_buffer_list.is_null() {
        unsafe {
            // 1. Get the MDL chain and free the memory
            let nb = NET_BUFFER_LIST_FIRST_NB(net_buffer_list);
            if !nb.is_null() {
                let mdl = NET_BUFFER_CURRENT_MDL(nb) as PMDL;
                if !mdl.is_null() {
                    let buffer_ptr =
                        MmGetSystemAddressForMdlSafe(mdl, _MM_PAGE_PRIORITY::HighPagePriority as u32);
                    if !buffer_ptr.is_null() {
                        ExFreePoolWithTag(buffer_ptr as *mut _, u32::from_be_bytes(*b"WDpk"));
                    }
                    IoFreeMdl(mdl);
                }
            }
            // 2. Free the NBL
            FwpsFreeNetBufferList0(net_buffer_list);
        }
    }
}

/// WFP injection completion function for NBLs created from user-mode buffers.
/// This function is responsible for unlocking the user buffer, freeing the MDL,
/// and completing the I/O request.
pub unsafe extern "C" fn injection_completion_fn_user_mdl(
    context: *mut core::ffi::c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: BOOLEAN,
) {
    unsafe {
        if !context.is_null() {
            let completion_context = &*(context as *mut UserInjectionCompletionContext);

            // Unlock the pages of the user buffer
            if !completion_context.mdl.is_null() {
                MmUnlockPages(completion_context.mdl);
                IoFreeMdl(completion_context.mdl);
            }

            // Complete the request
            if !completion_context.request.is_null() {
                WdfRequestComplete(completion_context.request, STATUS_SUCCESS);
            }

            // Free the completion context itself
            ExFreePoolWithTag(context as *mut _, u32::from_be_bytes(*b"UICx"));
        }

        if !net_buffer_list.is_null() {
            // Free the NBL. The associated MDL was already handled above.
            FwpsFreeNetBufferList0(net_buffer_list);
        }
    }
}

/// Allocates an empty NBL and returns the NBL pointer and a mutable pointer to the corresponding kernel buffer, facilitating direct zero-copy writes
pub fn allocate_empty_nbl(
    pool_handle: wdk_sys::HANDLE,
    data_len: usize,
) -> Option<(*mut NET_BUFFER_LIST, *mut u8)> {
    unsafe {
        if data_len == 0 {
            return None;
        }
        // 1. Allocate kernel memory
        let kernel_buffer = wdk_sys::ntddk::ExAllocatePool2(
            wdk_sys::POOL_FLAG_NON_PAGED,
            data_len as u64,
            u32::from_be_bytes(*b"WDpk"),
        );
        if kernel_buffer.is_null() {
            return None;
        }

        // 2. Allocate MDL
        let mdl = wdk_sys::ntddk::IoAllocateMdl(
            kernel_buffer as *mut _,
            data_len as u32,
            0, // SecondaryBuffer
            0, // ChargeQuota
            null_mut(),
        );
        if mdl.is_null() {
            ExFreePoolWithTag(kernel_buffer as *mut _, u32::from_be_bytes(*b"WDpk"));
            return None;
        }

        // 3. Build MDL memory mapping
        wdk_sys::ntddk::MmBuildMdlForNonPagedPool(mdl);

        // 4. Allocate NBL from WFP pool
        let mut nbl: *mut NET_BUFFER_LIST = null_mut();
        let status = FwpsAllocateNetBufferAndNetBufferList0(
            pool_handle as _,
            0, // ContextSize
            0, // ContextBackFill
            mdl as _,
            0, // DataOffset
            data_len as _,
            &mut nbl,
        );

        if !wdk::nt_success(status) {
            IoFreeMdl(mdl);
            ExFreePoolWithTag(kernel_buffer as *mut _, u32::from_be_bytes(*b"WDpk"));
            return None;
        }

        Some((nbl, kernel_buffer as *mut u8))
    }
}

/// Allocates an NBL for a given MDL, typically representing a user-mode buffer.
pub fn allocate_nbl_from_mdl(
    pool_handle: wdk_sys::HANDLE,
    mdl: PMDL,
    data_offset: usize,
    data_len: usize,
) -> Option<*mut NET_BUFFER_LIST> {
    unsafe {
        let mut nbl: *mut NET_BUFFER_LIST = null_mut();
        let status = FwpsAllocateNetBufferAndNetBufferList0(
            pool_handle as _,
            0, // ContextSize
            0, // ContextBackFill
            mdl as _,
            data_offset as u32,
            data_len as _,
            &mut nbl,
        );

        if wdk::nt_success(status) {
            Some(nbl)
        } else {
            None
        }
    }
}

pub fn inject_nbl(
    ctx_ptr: *mut crate::context::Context,
    is_inbound: bool,
    is_ipv6: bool,
    if_idx: u32,
    sub_if_idx: u32,
    nbl: *mut NET_BUFFER_LIST,
    completion_context: *mut core::ffi::c_void,
    is_user_mdl: bool,
) -> wdk_sys::NTSTATUS {
    unsafe {
        if nbl.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        let injection_handle;
        let compartment_id;

        if !is_inbound {
            // For outbound, compartment ID is typically 1 (Default), but can be specified.
            // We'll use the default compartment.
            compartment_id = 1;
            if is_ipv6 {
                injection_handle = (*ctx_ptr).network_ctx.inject_handle_out_v6;
            } else {
                injection_handle = (*ctx_ptr).network_ctx.inject_handle_out_v4;
            }
        } else {
            // inbound
            compartment_id = 1; // Default compartment
            if is_ipv6 {
                injection_handle = (*ctx_ptr).network_ctx.inject_handle_in_v6;
            } else {
                injection_handle = (*ctx_ptr).network_ctx.inject_handle_in_v4;
            }
        }

        let completion_fn: FWPS_INJECT_COMPLETE0 = if is_user_mdl {
            Some(injection_completion_fn_user_mdl)
        } else {
            Some(injection_completion_fn)
        };

        // Determine which injection function to use
        let status = if is_inbound {
            // Inject inbound packet
            FwpsInjectNetworkReceiveAsync0(
                injection_handle,
                null_mut(), // injection_context
                0,          // flags
                compartment_id as COMPARTMENT_ID,
                if_idx,
                0, // sub_interface_index
                nbl,
                completion_fn,
                completion_context,
            )
        } else {
            // Inject outbound packet
            FwpsInjectNetworkSendAsync0(
                injection_handle,
                null_mut(), // injection_context
                0,          // flags
                compartment_id as COMPARTMENT_ID,
                nbl,
                completion_fn,
                completion_context,
            )
        };

        if !wdk::nt_success(status) {
            // If injection fails, immediately call the completion function to clean up.
            if let Some(comp_fn) = completion_fn {
                comp_fn(completion_context, nbl, 0);
            }
            log!("FwpsInject failed: {:#010X}", status);
        }

        status
    }
}

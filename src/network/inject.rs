use crate::log;
use crate::wdk_ext::ndis::{
    FwpsAllocateNetBufferAndNetBufferList0, FwpsFreeNetBufferList0, NET_BUFFER_LIST,
};
use core::ptr::null_mut;
use wdk_sys::ntddk::{ExFreePoolWithTag, IoFreeMdl};
use wdk_sys::{
    BOOLEAN, PMDL, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, WDFREQUEST,
};
use crate::wdk_ext::wdf_wrapper::WdfRequestComplete;

/// Context for user-mode injection completion.
#[repr(C)]
pub struct UserInjectionCompletionContext {
    pub mdl: PMDL,
    pub request: WDFREQUEST,
}

/// WFP injection completion function for NBLs created from user-mode buffers.
/// This function is responsible for unlocking the user buffer, freeing the MDL,
/// and completing the I/O request.
pub unsafe extern "C" fn injection_completion_fn(
    context: *mut core::ffi::c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: BOOLEAN,
) {
    unsafe {
        if !context.is_null() {
            let completion_context = &*(context as *mut UserInjectionCompletionContext);

            // Free the MDL of the user buffer
            if !completion_context.mdl.is_null() {
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

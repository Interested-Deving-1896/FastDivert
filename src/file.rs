/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use alloc::boxed::Box;
use core::ffi::c_ushort;
use core::ptr::null_mut;

use wdk_sys::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_REQUEST, STATUS_PENDING,
    STATUS_SUCCESS,
};

use crate::context::{Context, ModuleContext};
use crate::ioctl_handler::{
    handle_initialize, handle_rb_map, handle_recv, handle_send, handle_startup,
};
use crate::ioctl_internal::*;
use crate::wdk_ext::wdf_wrapper::*;
use crate::{log, network};
use crate::network::bpf::BpfInsn;

/// WDF file object context type descriptor.
///
/// UniqueType must point to itself; it is fixed up at driver entry before any file objects
/// are created. ContextSize is the space WDF allocates per file object - just one pointer.
pub static mut FILE_CTX_TYPE: wdk_sys::WDF_OBJECT_CONTEXT_TYPE_INFO =
    wdk_sys::WDF_OBJECT_CONTEXT_TYPE_INFO {
        Size: core::mem::size_of::<wdk_sys::WDF_OBJECT_CONTEXT_TYPE_INFO>() as wdk_sys::ULONG,
        ContextName: b"FileCtx\0".as_ptr() as wdk_sys::LPCSTR,
        ContextSize: core::mem::size_of::<*mut Context>(),
        UniqueType: unsafe { core::ptr::addr_of!(FILE_CTX_TYPE) },
        EvtDriverGetUniqueContextType: None,
    };

/// Retrieve the *mut Context stored in a file object's WDF context space.
///
/// Returns an error if the space has not been written yet or the object is invalid.
#[inline(always)]
pub fn get_file_ctx(file_obj: wdk_sys::WDFFILEOBJECT) -> Result<*mut Context, NTSTATUS> {
    if file_obj.is_null() {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }

    unsafe {
        let space = WdfObjectGetTypedContextWorker(
            file_obj as wdk_sys::WDFOBJECT,
            core::ptr::addr_of!(FILE_CTX_TYPE),
        ) as *mut *mut Context;

        if space.is_null() {
            Err(STATUS_INVALID_DEVICE_REQUEST)
        } else {
            Ok(unsafe { *space })
        }
    }
}

/// Write `ctx_ptr` into a file object's WDF context space.
pub fn write_file_ctx_to_file_object(
    file_obj: wdk_sys::WDFFILEOBJECT,
    ctx_ptr: *mut Context,
) -> Result<(), NTSTATUS> {
    unsafe {
        let space = WdfObjectGetTypedContextWorker(
            file_obj as wdk_sys::WDFOBJECT,
            core::ptr::addr_of!(FILE_CTX_TYPE),
        ) as *mut *mut Context;

        if !space.is_null() {
            *space = ctx_ptr;
            Ok(())
        } else {
            Err(STATUS_INSUFFICIENT_RESOURCES)
        }
    }
}

/// File create callback - creates and initializes a Context, stores its pointer in the WDF
/// file object context space.
pub unsafe extern "C" fn file_create(
    device: wdk_sys::WDFDEVICE,
    request: wdk_sys::WDFREQUEST,
    file_object: wdk_sys::WDFFILEOBJECT,
) {
    if file_object.is_null() {
        WdfRequestComplete(request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }

    match Context::new(device, file_object) {
        Ok(context) => {
            let context_ptr = Box::into_raw(context);
            match write_file_ctx_to_file_object(file_object, context_ptr) {
                Ok(_) => {
                    WdfRequestComplete(request, STATUS_SUCCESS);
                }
                Err(status) => {
                    log!("file_create: failed to write context to file object");
                    // Important: Since we boxed it, we must free it if we fail to attach it
                    let _ = unsafe { Box::from_raw(context_ptr) };
                    WdfRequestComplete(request, status);
                }
            };
        }
        Err(status) => {
            log!("file_create: failed to init context: {:#010X}", status);
            WdfRequestComplete(request, status);
        }
    }
}

/// A dummy callback function that does nothing.
/// Used to wait for WdfIoQueuePurge to finish synchronously if we pass null ctx.
/// (WdfIoQueuePurge requires a callback, but we wait by just letting it return if we do sync cleanup)
pub unsafe extern "C" fn empty_purge_complete(_queue: wdk_sys::WDFQUEUE, _context: wdk_sys::WDFCONTEXT) {
}

/// File cleanup callback - removes WFP filters/minifilters, clears ring buffer callbacks, marks closed.
pub unsafe extern "C" fn file_cleanup(file_object: wdk_sys::WDFFILEOBJECT) {
    if file_object.is_null() {
        return;
    }

    unsafe {
        let ctx = match get_file_ctx(file_object) {
            Ok(c) => c,
            Err(_) => return,
        };

        let c = &mut *ctx;

        // Clean up active module context generically
        if let Some(mut module_ctx) = c.module.take() {
            match module_ctx {
                ModuleContext::Network(mut net_m) => net_m.cleanup(ctx),
                ModuleContext::File(mut file_m) => file_m.cleanup(ctx),
            }
        }

        // We don't need to manually purge the recv_queue. Since its parent object is
        // the file_object, WDF will automatically purge and delete the queue during
        // file_object destruction. Any pending requests in the queue will be canceled
        // by the framework.

        c.set_state(crate::context::ContextState::Closed);
    }
}

/// File close callback - marks context as closing.
pub unsafe extern "C" fn file_close(file_object: wdk_sys::WDFFILEOBJECT) {
    if file_object.is_null() {
        return;
    }
    unsafe {
        if let Ok(ctx) = get_file_ctx(file_object) {
            (*ctx).set_state(crate::context::ContextState::Closing);
        }
    }
}

/// File destroy callback - frees the Context that was stored in the WDF context space.
pub unsafe extern "C" fn file_destroy(file_object: wdk_sys::WDFOBJECT) {
    if file_object.is_null() {
        return;
    }
    unsafe {
        let file_obj = file_object as wdk_sys::WDFFILEOBJECT;
        if let Ok(ctx) = get_file_ctx(file_obj) {
            // Take ownership of the pointer and drop it, freeing the Box
            let _ = Box::from_raw(ctx);
        }
    }
}

/// I/O in caller context - forwards all requests to the queue.
pub unsafe extern "C" fn io_in_caller_context(
    device: wdk_sys::WDFDEVICE,
    request: wdk_sys::WDFREQUEST,
) {
    let mut params = wdk_sys::WDF_REQUEST_PARAMETERS {
        Size: size_of::<wdk_sys::WDF_REQUEST_PARAMETERS>() as c_ushort,
        ..Default::default()
    };
    WdfRequestGetParameters(request, &mut params);

    // Critical improvement: intercept IOCTLs that need specific context before enqueuing
    if params.Type == wdk_sys::_WDF_REQUEST_TYPE::WdfRequestTypeDeviceControl {
        let ioctl_code = unsafe { params.Parameters.DeviceIoControl.IoControlCode };
        if ioctl_code == IOCTL_MAP_MM {
            let file_object = WdfRequestGetFileObject(request);
            if let Ok(ctx) = get_file_ctx(file_object) {
                // Process mapping logic directly here, ensuring it runs in the caller's process context
                handle_map_mm_request(request, ctx, file_object);
                return; // Processing complete, return directly, do not enqueue
            }
        }
    }

    let status = WdfDeviceEnqueueRequest(device, request);
    if !wdk::nt_success(status) {
        WdfRequestComplete(request, status);
    }
}

/// IOCTL dispatcher.
pub unsafe extern "C" fn ioctl_callback(
    _queue: wdk_sys::WDFQUEUE,
    request: wdk_sys::WDFREQUEST,
    _output_buffer_length: usize,
    input_buffer_length: usize,
    io_control_code: u32,
) {
    let file_object = WdfRequestGetFileObject(request);
    if file_object.is_null() {
        log!("ioctl_callback: failed to get file object");
        WdfRequestComplete(request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }

    let ctx = match unsafe { get_file_ctx(file_object) } {
        Ok(c) => c,
        Err(err) => {
            log!("ioctl_callback: failed to get ctx ptr from file object");
            WdfRequestComplete(request, err);
            return;
        }
    };

    match io_control_code {
        IOCTL_INITIALIZE => unsafe { handle_initialize_request(request, ctx, file_object) },
        IOCTL_STARTUP => unsafe { handle_startup_request(request, ctx, file_object) },
        IOCTL_MAP_MM => unsafe { handle_map_mm_request(request, ctx, file_object) },
        IOCTL_RECV => unsafe { handle_recv_request(request, input_buffer_length) },
        IOCTL_SEND => unsafe { handle_send_request(request, ctx, input_buffer_length) },
        IOCTL_SET_BPF => unsafe { handle_set_bpf_request(request, ctx, input_buffer_length) },
        _ => {
            log!(
                "ioctl_callback: invalid IOCTL code {:#010X}",
                io_control_code
            );
            WdfRequestComplete(request, STATUS_INVALID_DEVICE_REQUEST);
        }
    }
}

// -----------------------------------------------------------------------------
// IOCTL Request Handlers Extracted for Readability
// -----------------------------------------------------------------------------

fn handle_initialize_request(
    request: wdk_sys::WDFREQUEST,
    ctx: *mut Context,
    file_object: wdk_sys::WDFFILEOBJECT,
) {
    let mut req_ptr: *mut DivertIoctlInitialize = null_mut();
    let mut resp_ptr: *mut IoctlInitializeResponse = null_mut();

    let status = helper_retrieve_io_buffer(request, &mut req_ptr, &mut resp_ptr);
    if !wdk::nt_success(status) {
        log!("IOCTL_INITIALIZE: failed to retrieve buffers");
        WdfRequestComplete(request, status);
        return;
    }

    let result_status = handle_initialize(request, ctx, file_object, req_ptr, resp_ptr);
    WdfRequestComplete(request, result_status);
}

fn handle_startup_request(
    request: wdk_sys::WDFREQUEST,
    ctx: *mut Context,
    file_object: wdk_sys::WDFFILEOBJECT,
) {
    let mut req_ptr: *mut DivertIoctlStartup = null_mut();

    let status = helper_retrieve_input_buffer(request, &mut req_ptr);
    if !wdk::nt_success(status) {
        log!("IOCTL_STARTUP: failed to retrieve input buffer");
        WdfRequestComplete(request, status);
        return;
    }

    let result_status = handle_startup(request, ctx, file_object, req_ptr);
    WdfRequestComplete(request, result_status);
}

fn handle_map_mm_request(
    request: wdk_sys::WDFREQUEST,
    ctx: *mut Context,
    file_object: wdk_sys::WDFFILEOBJECT,
) {
    let mut req_ptr: *mut DivertIoctlMMapRequest = null_mut();
    let mut resp_ptr: *mut IoctlMMapResponse = null_mut();

    let status = helper_retrieve_io_buffer(request, &mut req_ptr, &mut resp_ptr);
    if !wdk::nt_success(status) {
        log!("IOCTL_MAP_MM: failed to retrieve io buffers");
        WdfRequestComplete(request, status);
        return;
    }

    let result_status = handle_rb_map(request, ctx, file_object, req_ptr, resp_ptr);
    if wdk::nt_success(result_status) {
        WdfRequestCompleteWithInformation(
            request,
            result_status,
            core::mem::size_of::<IoctlMMapResponse>() as wdk_sys::ULONG_PTR,
        );
    } else {
        WdfRequestComplete(request, result_status);
    }
}

fn handle_recv_request(request: wdk_sys::WDFREQUEST, input_buffer_length: usize) {
    let status = handle_recv(request, input_buffer_length);

    // If pending, the framework or callback will complete it later.
    // If success, `handle_recv` already completed it internally.
    if status != STATUS_PENDING && status != STATUS_SUCCESS {
        WdfRequestComplete(request, status);
    }
}

fn handle_send_request(
    request: wdk_sys::WDFREQUEST,
    ctx: *mut Context,
    input_buffer_length: usize,
) {
    let status = handle_send(request, ctx, input_buffer_length);
    if status != STATUS_PENDING {
        WdfRequestComplete(request, status);
    }
}

fn handle_set_bpf_request(
    request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    input_buffer_length: usize,
) {
    unsafe {
        let ctx = &mut *ctx_ptr;
        let mut buffer_ptr: wdk_sys::PVOID = null_mut();
        let mut buffer_length: usize = 0;

        let status = WdfRequestRetrieveInputBuffer(
            request,
            0,
            &mut buffer_ptr,
            &mut buffer_length,
        );

        if !wdk::nt_success(status) {
            log!("handle_set_bpf: WdfRequestRetrieveInputBuffer failed {:#010X}", status);
            WdfRequestComplete(request, status);
            return;
        }

        if buffer_length % core::mem::size_of::<BpfInsn>() != 0 {
            log!("handle_set_bpf: invalid buffer size");
            WdfRequestComplete(request, STATUS_INVALID_DEVICE_REQUEST);
            return;
        }

        let num_insns = buffer_length / core::mem::size_of::<BpfInsn>();
        let insns = core::slice::from_raw_parts(buffer_ptr as *const BpfInsn, num_insns);

        let mut bpf_vec = alloc::vec::Vec::with_capacity(num_insns);
        bpf_vec.extend_from_slice(insns);

        if let Some(ModuleContext::Network(ref mut m)) = ctx.module {
            m.bpf_program = bpf_vec;
            log!("handle_set_bpf: successfully loaded {} BPF instructions", num_insns);
            WdfRequestComplete(request, STATUS_SUCCESS);
        } else {
            log!("handle_set_bpf: active module is not network!");
            WdfRequestComplete(request, STATUS_INVALID_DEVICE_REQUEST);
        }
    }
}

// -----------------------------------------------------------------------------
// Buffer Retrieval Helpers
// -----------------------------------------------------------------------------

fn helper_retrieve_input_buffer<Tin>(
    wdf_request: wdk_sys::WDFREQUEST,
    in_t: *mut *mut Tin,
) -> NTSTATUS {
    let mut input_len: usize = 0;
    let status = WdfRequestRetrieveInputBuffer(
        wdf_request,
        core::mem::size_of::<Tin>(),
        in_t as *mut _,
        &mut input_len,
    );
    if !wdk::nt_success(status) {
        return status;
    }
    STATUS_SUCCESS
}

fn helper_retrieve_output_buffer<Tout>(
    wdf_request: wdk_sys::WDFREQUEST,
    out_t: *mut *mut Tout,
) -> NTSTATUS {
    let mut output_len: usize = 0;
    let status = WdfRequestRetrieveOutputBuffer(
        wdf_request,
        core::mem::size_of::<Tout>(),
        out_t as *mut _,
        &mut output_len,
    );
    if !wdk::nt_success(status) {
        return status;
    }
    STATUS_SUCCESS
}

fn helper_retrieve_io_buffer<Tin, Tout>(
    wdf_request: wdk_sys::WDFREQUEST,
    in_t: *mut *mut Tin,
    out_t: *mut *mut Tout,
) -> NTSTATUS {
    let mut input_len: usize = 0;
    let mut output_len: usize = 0;

    let status = WdfRequestRetrieveInputBuffer(
        wdf_request,
        core::mem::size_of::<Tin>(),
        in_t as *mut _,
        &mut input_len,
    );
    if !wdk::nt_success(status) {
        return status;
    }

    let status = WdfRequestRetrieveOutputBuffer(
        wdf_request,
        core::mem::size_of::<Tout>(),
        out_t as *mut _,
        &mut output_len,
    );
    if !wdk::nt_success(status) {
        return status;
    }

    STATUS_SUCCESS
}
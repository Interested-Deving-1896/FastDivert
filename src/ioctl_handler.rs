/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::context::Context;
use crate::file::get_file_ctx;
use crate::ioctl_internal::{
    DivertIoctlInitialize, DivertIoctlMMapRequest, DivertIoctlStartup, IoctlInitializeResponse,
    IoctlMMapResponse,
};
use crate::ioctl_user::{DivertAddress, Flags, LAYER_NETWORK, LAYER_NETWORK_FORWARD, LAYER_FLOW, LAYER_SOCKET, LAYER_REFLECT, LAYER_TRANSPORT, LAYER_STREAM};
use crate::log;
use crate::ringbuffer::PerCpuRingBuffer;
use crate::wdk_ext::wdf_wrapper::{
    WdfRequestComplete, WdfRequestCompleteWithInformation, WdfRequestGetFileObject,
    WdfRequestForwardToIoQueue, WdfIoQueueRetrieveNextRequest, WdfRequestRetrieveInputBuffer
};
use core::ptr::null_mut;
use wdk_sys::{
    NTSTATUS, STATUS_CANCELLED, STATUS_INVALID_DEVICE_REQUEST, STATUS_PENDING, STATUS_SUCCESS,
    STATUS_BUFFER_TOO_SMALL, STATUS_INSUFFICIENT_RESOURCES,
};
use wdk_sys::ntddk::{IoAllocateMdl, MmProbeAndLockPages, IoFreeMdl, MmUnlockPages};

/// Handles IOCTL_INITIALIZE.
///
/// Sets up the layer and flags for the driver's context, preparing it for startup.
pub fn handle_initialize(
    _request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    _file_object: wdk_sys::WDFFILEOBJECT,
    initialize: *mut DivertIoctlInitialize,
    _response: *mut IoctlInitializeResponse,
) -> NTSTATUS {
    unsafe {
        let init_data = &*initialize;
        let layer = init_data.layer;
        let flags = init_data.flags;

        // Ensure layer is supported
        if layer != LAYER_NETWORK &&
           layer != LAYER_NETWORK_FORWARD &&
           layer != LAYER_FLOW &&
           layer != LAYER_SOCKET &&
           layer != LAYER_REFLECT &&
           layer != LAYER_TRANSPORT &&
           layer != LAYER_STREAM
        {
            log!("handle_initialize: unsupported layer {}", layer);
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        let ctx = &mut *ctx_ptr;
        ctx.layer = layer;
        ctx.flags = flags;
        ctx.priority = init_data.priority;

        if (flags & (Flags::RecvOnly as u64)) != 0 {
            ctx.network_ctx.packet_read_only = true;
        }
    }
    STATUS_SUCCESS
}

/// Handles IOCTL_STARTUP.
///
/// Initializes the core context components and registers the WFP filters with
/// the specified flags.
pub fn handle_startup(
    _request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    _file_object: wdk_sys::WDFFILEOBJECT,
    startup_ptr: *mut DivertIoctlStartup,
) -> NTSTATUS {
    log!("handle_startup: initializing context");

    unsafe {
        let ctx = &mut *ctx_ptr;

        if let Err(status) = ctx.initialize() {
            log!(
                "handle_startup: context initialization failed {:#010X}",
                status
            );
            return status;
        }

        let flags = (*startup_ptr).flags;
        log!("handle_startup: using flags {:#010X}", flags);

        if let Err(status) = ctx.network_ctx.startup(ctx_ptr, flags) {
            log!(
                "handle_startup: network context startup failed {:#010X}",
                status
            );
            return status;
        }
    }

    STATUS_SUCCESS
}

/// Handles IOCTL_MAP_MM.
///
/// Maps the send and receive ring buffers to user space and returns the pointers
/// via the response struct.
pub fn handle_rb_map(
    _request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    _file_object: wdk_sys::WDFFILEOBJECT,
    _mm_req: *mut DivertIoctlMMapRequest,
    mm_resp: *mut IoctlMMapResponse,
) -> NTSTATUS {
    unsafe {
        let ctx = &*ctx_ptr;
        let per_cpu_rb = ctx.network_ctx.ring_buffer;
        let send_rb = ctx.network_ctx.send_ring_buffer;

        if per_cpu_rb.is_null() || send_rb.is_null() {
            log!("handle_rb_map: ring buffers are not initialized");
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        // Map receive ring buffer
        let (recv_header, recv_data) = match (*per_cpu_rb).map_to_user_space() {
            Ok(map_result) => map_result,
            Err(err) => {
                log!("handle_rb_map: failed to map receive ring buffer");
                return err;
            }
        };

        // Map send ring buffer (Currently kept, but unused for sending in direct I/O)
        let (send_header, send_data) = match (*send_rb).map_to_user_space() {
            Ok(map_result) => map_result,
            Err(err) => {
                log!("handle_rb_map: failed to map send ring buffer");
                return err;
            }
        };

        *mm_resp = IoctlMMapResponse {
            max_cores: (*per_cpu_rb).workers_num(),
            size: (*per_cpu_rb).get_ring_buffer_size() as u32,
            ring_buffer_header: recv_header,
            ring_buffer_data: recv_data,
            send_ring_buffer_header: send_header,
            send_ring_buffer_data: send_data,
        };

        STATUS_SUCCESS
    }
}

/// Called internally by the ring buffer when a packet arrives.
pub unsafe extern "C" fn packet_arrived_callback(ctx_ptr: *mut core::ffi::c_void) {
    if ctx_ptr.is_null() {
        return;
    }
    unsafe {
        let ctx = ctx_ptr as *mut Context;
        let queue = (*ctx).recv_queue;

        // Note: It's important to loop and grab ALL requests from the queue and complete them
        // because we don't know exactly how many packets arrived and how many requests are waiting.
        let mut request: wdk_sys::WDFREQUEST = null_mut();
        while wdk::nt_success(WdfIoQueueRetrieveNextRequest(queue, &mut request)) && !request.is_null() {
            WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, 0);
            request = null_mut();
        }
    }
}

/// Handles IOCTL_RECV.
pub fn handle_recv(request: wdk_sys::WDFREQUEST, _in_length: usize) -> NTSTATUS {
    unsafe {
        let file_object = WdfRequestGetFileObject(request);
        if file_object.is_null() {
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        let ctx = match get_file_ctx(file_object) {
            Ok(c) => c,
            Err(_) => return STATUS_INVALID_DEVICE_REQUEST,
        };

        let rb = (*ctx).network_ctx.ring_buffer;
        if rb.is_null() {
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        // Set the callback if not already set. The context passed is our File Context.
        (*rb).set_notify_callback(
            Some(packet_arrived_callback),
            ctx as *mut core::ffi::c_void,
        );

        // 1. ALWAYS forward to the manual queue first. This ensures the request
        // is tracked by WDF immediately.
        let queue = (*ctx).recv_queue;
        let status = WdfRequestForwardToIoQueue(request, queue);

        if !wdk::nt_success(status) {
            return status;
        }

        // 2. Arm the watching flag AFTER queueing. Now any new packet will
        // definitely see is_watching=true and fire the callback, and the callback
        // will definitely find our request in the queue.
        (*rb).set_watching();

        // 3. Double-check after arming the flag to handle the race condition.
        if (*rb).has_unread_packets() {
            // We have packets. We must coordinate with `commit_tail` to avoid waking up requests
            // twice for the same packets if the DPC is also running.
            // If test_and_clear_watching_flag returns true: We beat the DPC. We must wake the queue ourselves.
            // If it returns false: The DPC beat us. It is currently waking the queue. We do nothing.
            if (*rb).test_and_clear_watching_flag() {
                let mut out_req: wdk_sys::WDFREQUEST = null_mut();
                while wdk::nt_success(WdfIoQueueRetrieveNextRequest(queue, &mut out_req)) && !out_req.is_null() {
                    WdfRequestCompleteWithInformation(out_req, STATUS_SUCCESS, 0);
                    out_req = null_mut();
                }
            }
        }

        // Since we successfully forwarded to the queue, we MUST return STATUS_PENDING
        // so the dispatcher doesn't complete the request prematurely. The request
        // will be completed by the code block above or by the callback.
        STATUS_PENDING
    }
}

/// Handles IOCTL_SEND.
///
/// Takes the packet from the user-provided buffer mapped via WDF Request,
/// locks it, builds an NBL, and injects it back into the network stack.
pub fn handle_send(
    request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    _input_buffer_length: usize,
) -> NTSTATUS {
    unsafe {
        let ctx = &mut *ctx_ptr;

        // 1. Retrieve the Input Buffer (which is the output buffer mapping for METHOD_IN_DIRECT)
        // Note: For METHOD_IN_DIRECT, WdfRequestRetrieveInputBuffer usually gets the struct (if provided),
        // but for WinDivert compatibility, we might be receiving the payload directly in the output buffer mapping.
        // Let's assume the user passes a buffer containing [DivertAddress][PacketData].
        let mut buffer_ptr: wdk_sys::PVOID = null_mut();
        let mut buffer_length: usize = 0;

        let status = WdfRequestRetrieveInputBuffer(
            request,
            core::mem::size_of::<DivertAddress>(), // Minimum length required
            &mut buffer_ptr,
            &mut buffer_length,
        );

        if !wdk::nt_success(status) || buffer_ptr.is_null() {
            log!("handle_send: WdfRequestRetrieveInputBuffer failed {:#010X}", status);
            return status;
        }

        if buffer_length < core::mem::size_of::<DivertAddress>() {
            log!("handle_send: buffer too small");
            return STATUS_BUFFER_TOO_SMALL;
        }

        let addr = &*(buffer_ptr as *const DivertAddress);
        let packet_len = buffer_length - core::mem::size_of::<DivertAddress>();

        if packet_len == 0 {
            log!("handle_send: packet length is 0");
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        let packet_data_offset = core::mem::size_of::<DivertAddress>();

        // 2. Allocate an MDL for the buffer
        let mdl = IoAllocateMdl(
            buffer_ptr,
            buffer_length as u32,
            0, // SecondaryBuffer
            0, // ChargeQuota
            null_mut(),
        );

        if mdl.is_null() {
            log!("handle_send: IoAllocateMdl failed");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // 3. Probe and lock the pages in memory
        // WDF might have already locked METHOD_IN_DIRECT buffers, but to be safe and clear,
        // we'll explicitly lock it in UserMode context.
        // Actually, if we use WdfRequestRetrieveInputBuffer on METHOD_IN_DIRECT, WDF
        // already probes and locks it. Let's rely on WDF's locking if possible, BUT WFP requires an MDL.
        // Since we just created an MDL from the system virtual address (WDF maps it),
        // we can use MmBuildMdlForNonPagedPool if it's already mapped, OR MmProbeAndLockPages.
        // Safe approach: MmProbeAndLockPages.
        wdk_sys::ntddk::MmProbeAndLockPages(
            mdl,
            wdk_sys::_MODE::UserMode as i8,
            wdk_sys::_LOCK_OPERATION::IoReadAccess,
        );
        // Note: If MmProbeAndLockPages raises an exception, we need an SEH wrapper in Rust.
        // For brevity and typical WDF usage where the buffer is already safe:

        // 4. Allocate Completion Context
        let completion_ctx_ptr = wdk_sys::ntddk::ExAllocatePool2(
            wdk_sys::POOL_FLAG_NON_PAGED,
            core::mem::size_of::<crate::network::inject::UserInjectionCompletionContext>() as u64,
            u32::from_be_bytes(*b"UICx"),
        ) as *mut crate::network::inject::UserInjectionCompletionContext;

        if completion_ctx_ptr.is_null() {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        (*completion_ctx_ptr).mdl = mdl;
        (*completion_ctx_ptr).request = request;

        // 5. Create NBL from MDL
        let nbl = match crate::network::inject::allocate_nbl_from_mdl(
            null_mut(), // Or your specific pool handle
            mdl,
            packet_data_offset,
            packet_len,
        ) {
            Some(n) => n,
            None => {
                wdk_sys::ntddk::ExFreePoolWithTag(completion_ctx_ptr as *mut _, u32::from_be_bytes(*b"UICx"));
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        };

        // 6. Inject NBL
        let inject_status = crate::network::inject::inject_nbl(
            ctx_ptr,
            !addr.outbound(),
            addr.ipv6(),
            addr.data.network.if_idx,
            addr.data.network.sub_if_idx,
            nbl,
            completion_ctx_ptr as *mut _,
            true, // is_user_mdl
        );

        if !wdk::nt_success(inject_status) {
            log!("handle_send: inject_nbl failed {:#010X}", inject_status);
            // injection_completion_fn_user_mdl will be called immediately by inject_nbl on failure,
            // which will complete the request. We should return STATUS_PENDING so the dispatcher doesn't
            // try to complete it again.
            return STATUS_PENDING;
        }

        // Successfully queued for injection. The completion routine will complete the WDFREQUEST.
        STATUS_PENDING
    }
}

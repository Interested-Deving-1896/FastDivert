/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::context::{Context, ModuleContext};
use crate::file::get_file_ctx;
use crate::ioctl_internal::{
    DivertIoctlInitialize, DivertIoctlMMapRequest, DivertIoctlStartup, IoctlInitializeResponse,
    IoctlMMapResponse, FileModuleConfig,
};
use crate::ioctl_user::{
    DivertAddress, Flags, LAYER_NETWORK, LAYER_NETWORK_FORWARD, LAYER_FLOW, LAYER_SOCKET,
    LAYER_REFLECT, LAYER_TRANSPORT, LAYER_STREAM, LAYER_FILE,
};
use crate::network::module::NetworkModule;
use crate::file_monitor::file_module::FileModule;
use crate::log;
use crate::wdk_ext::wdf_wrapper::{
    WdfRequestComplete, WdfRequestCompleteWithInformation, WdfRequestGetFileObject,
    WdfRequestForwardToIoQueue, WdfIoQueueRetrieveNextRequest, WdfRequestRetrieveInputBuffer
};
use core::ptr::null_mut;
use wdk_sys::{
    NTSTATUS, STATUS_CANCELLED, STATUS_INVALID_DEVICE_REQUEST, STATUS_PENDING, STATUS_SUCCESS,
    STATUS_BUFFER_TOO_SMALL, STATUS_INSUFFICIENT_RESOURCES,
};

/// Handles IOCTL_INITIALIZE.
///
/// Allocates and instantiates the appropriate module context (Network or File) based on the requested layer.
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
           layer != LAYER_STREAM &&
           layer != LAYER_FILE
        {
            log!("handle_initialize: unsupported layer {}", layer);
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        let ctx = &mut *ctx_ptr;
        ctx.layer = layer;
        ctx.flags = flags;
        ctx.priority = init_data.priority;

        // Instantiate appropriate module context
        if layer == LAYER_FILE {
            match FileModule::new() {
                Ok(m) => {
                    ctx.module = Some(ModuleContext::File(alloc::boxed::Box::new(m)));
                    log!("handle_initialize: successfully instantiated FileModule");
                }
                Err(status) => {
                    log!("handle_initialize: failed to allocate FileModule: {:#010X}", status);
                    return status;
                }
            }
        } else {
            match NetworkModule::new(layer) {
                Ok(m) => {
                    ctx.module = Some(ModuleContext::Network(alloc::boxed::Box::new(m)));
                    log!("handle_initialize: successfully instantiated NetworkModule for layer {}", layer);
                }
                Err(status) => {
                    log!("handle_initialize: failed to allocate NetworkModule: {:#010X}", status);
                    return status;
                }
            }
        }
    }
    STATUS_SUCCESS
}

/// Handles IOCTL_STARTUP.
///
/// Initializes the core context components and delegates startup to the active module.
pub fn handle_startup(
    request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    _file_object: wdk_sys::WDFFILEOBJECT,
    startup_ptr: *mut DivertIoctlStartup,
) -> NTSTATUS {
    log!("handle_startup: initializing context");

    unsafe {
        let ctx = &mut *ctx_ptr;

        if let Err(status) = ctx.initialize() {
            log!("handle_startup: context initialization failed {:#010X}", status);
            return status;
        }

        let flags = if (*startup_ptr).flags != 0 {
            (*startup_ptr).flags
        } else {
            ctx.flags
        };
        log!("handle_startup: using flags {:#010X}", flags);

        // If the active module is the file monitor, extract the FileModuleConfig configuration
        if ctx.layer == LAYER_FILE {
            let mut input_ptr: wdk_sys::PVOID = null_mut();
            let mut input_len: usize = 0;
            let status = WdfRequestRetrieveInputBuffer(
                request,
                size_of::<FileModuleConfig>(),
                &mut input_ptr,
                &mut input_len,
            );
            if !wdk::nt_success(status) {
                log!("handle_startup: WdfRequestRetrieveInputBuffer failed {:#010X}", status);
                return status;
            }
            if input_len < size_of::<FileModuleConfig>() {
                log!("handle_startup: input buffer too small for FileModuleConfig");
                return STATUS_BUFFER_TOO_SMALL;
            }
            let config = input_ptr as *const FileModuleConfig;
            if (*config).rule_count > crate::ioctl_internal::MAX_FILTER_RULES as u32 {
                log!("handle_startup: rule_count {} exceeds MAX_FILTER_RULES {}", (*config).rule_count, crate::ioctl_internal::MAX_FILTER_RULES);
                return wdk_sys::STATUS_INVALID_PARAMETER;
            }
            for i in 0..(*config).rule_count as usize {
                if (*config).rules[i].path_len as usize > crate::ioctl_internal::MAX_RULE_PATH_LEN {
                    log!("handle_startup: rule {} path_len {} exceeds MAX_RULE_PATH_LEN", i, (*config).rules[i].path_len);
                    return wdk_sys::STATUS_INVALID_PARAMETER;
                }
            }
            if let Some(ModuleContext::File(ref mut m)) = ctx.module {
                core::ptr::copy_nonoverlapping(config, &mut *m.config as *mut FileModuleConfig, 1);
            }
        }

        // Delegate to active module
        if let Some(ref mut m) = ctx.module {
            let res = match m {
                ModuleContext::Network(net_m) => net_m.startup(ctx_ptr, flags),
                ModuleContext::File(file_m) => file_m.startup(ctx_ptr, flags),
            };
            match res {
                Ok(_) => STATUS_SUCCESS,
                Err(status) => {
                    log!("handle_startup: active module startup failed {:#010X}", status);
                    status
                }
            }
        } else {
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// Handles IOCTL_MAP_MM.
///
/// Delegates memory mapping to the active module.
pub fn handle_rb_map(
    _request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    _file_object: wdk_sys::WDFFILEOBJECT,
    _mm_req: *mut DivertIoctlMMapRequest,
    mm_resp: *mut IoctlMMapResponse,
) -> NTSTATUS {
    unsafe {
        let ctx = &*ctx_ptr;
        if let Some(ref m) = ctx.module {
            let res = match m {
                ModuleContext::Network(net_m) => net_m.map_memory(),
                ModuleContext::File(file_m) => file_m.map_memory(),
            };
            match res {
                Ok(resp) => {
                    *mm_resp = resp;
                    STATUS_SUCCESS
                }
                Err(status) => {
                    log!("handle_rb_map: active module map_memory failed {:#010X}", status);
                    status
                }
            }
        } else {
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// Handles IOCTL_RECV.
///
/// Delegates notification callback arming to the active module.
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

        let queue = (*ctx).recv_queue;
        let status = WdfRequestForwardToIoQueue(request, queue);

        if !wdk::nt_success(status) {
            return status;
        }

        if let Some(ref m) = (*ctx).module {
            let res = match m {
                ModuleContext::Network(net_m) => net_m.arm_recv(ctx),
                ModuleContext::File(file_m) => file_m.arm_recv(ctx),
            };
            match res {
                Ok(_) => STATUS_PENDING,
                Err(status) => status,
            }
        } else {
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// Handles IOCTL_SEND.
///
/// Delegates user-space write/decision processing to the active module.
pub fn handle_send(
    request: wdk_sys::WDFREQUEST,
    ctx_ptr: *mut Context,
    input_buffer_length: usize,
) -> NTSTATUS {
    unsafe {
        let ctx = &*ctx_ptr;
        if let Some(ref m) = ctx.module {
            match m {
                ModuleContext::Network(net_m) => net_m.handle_send(ctx_ptr, request, input_buffer_length),
                ModuleContext::File(file_m) => file_m.handle_send(ctx_ptr, request, input_buffer_length),
            }
        } else {
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}
/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

#![allow(non_camel_case_types, non_snake_case)]

use wdk_sys::NTSTATUS;

pub fn WdfDriverCreate(
    driver_object: wdk_sys::PDRIVER_OBJECT,
    registry_path: wdk_sys::PCUNICODE_STRING,
    attr: wdk_sys::PWDF_OBJECT_ATTRIBUTES,
    config: wdk_sys::PWDF_DRIVER_CONFIG,
    wfp_driver: *mut wdk_sys::WDFDRIVER,
) -> i32 {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfDriverCreate,
            driver_object,
            registry_path,
            attr,
            config,
            wfp_driver,
        )
    }
}
pub fn WdfDeviceCreate(
    device_init: *mut wdk_sys::PWDFDEVICE_INIT,
    device_attributes: wdk_sys::PWDF_OBJECT_ATTRIBUTES,
    device: *mut wdk_sys::WDFDEVICE,
) -> i32 {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfDeviceCreate,
            device_init,
            device_attributes,
            device
        )
    }
}

pub fn WdfDeviceCreateSymbolicLink(
    device: wdk_sys::WDFDEVICE,
    symbolic_link_name: wdk_sys::PCUNICODE_STRING,
) -> i32 {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfDeviceCreateSymbolicLink,
            device,
            symbolic_link_name
        )
    }
}

pub fn WdfControlDeviceInitAllocate(
    driver: wdk_sys::WDFDRIVER,
    sd_dl_string: wdk_sys::PCUNICODE_STRING,
) -> *mut wdk_sys::WDFDEVICE_INIT {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfControlDeviceInitAllocate,
            driver,
            sd_dl_string,
        )
    }
}
pub fn WdfDeviceInitSetDeviceType(device_init: wdk_sys::PWDFDEVICE_INIT, device_type: u32) {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetDeviceType,
            device_init,
            device_type
        )
    }
}

pub fn WdfDeviceInitSetIoType(
    device_init: wdk_sys::PWDFDEVICE_INIT,
    io_type: wdk_sys::WDF_DEVICE_IO_TYPE,
) {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(WdfDeviceInitSetIoType, device_init, io_type)
    }
}

pub fn WdfDeviceInitAssignName(
    device_init: wdk_sys::PWDFDEVICE_INIT,
    device_name: wdk_sys::PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfDeviceInitAssignName,
            device_init,
            device_name
        )
    }
}

pub fn WdfDeviceInitFree(device_init: wdk_sys::PWDFDEVICE_INIT) {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfDeviceInitFree, device_init) }
}

pub fn WdfDeviceInitSetFileObjectConfig(
    device_init: wdk_sys::PWDFDEVICE_INIT,
    file_object_config: wdk_sys::PWDF_FILEOBJECT_CONFIG,
    attr: wdk_sys::PWDF_OBJECT_ATTRIBUTES,
) {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetFileObjectConfig,
            device_init,
            file_object_config,
            attr
        )
    }
}

pub fn WdfDeviceInitSetIoInCallerContextCallback(
    device_init: wdk_sys::PWDFDEVICE_INIT,
    evt_io_in_caller_context: wdk_sys::PFN_WDF_IO_IN_CALLER_CONTEXT,
) {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetIoInCallerContextCallback,
            device_init,
            evt_io_in_caller_context
        )
    }
}

pub fn WdfIoQueueCreate(
    device: wdk_sys::WDFDEVICE,
    config: wdk_sys::PWDF_IO_QUEUE_CONFIG,
    attr: wdk_sys::PWDF_OBJECT_ATTRIBUTES,
    queue: *mut wdk_sys::WDFQUEUE,
) -> i32 {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(WdfIoQueueCreate, device, config, attr, queue)
    }
}

pub fn WdfControlFinishInitializing(device: wdk_sys::WDFDEVICE) {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfControlFinishInitializing, device) }
}

pub fn WdfRequestRetrieveInputBuffer(
    request: wdk_sys::WDFREQUEST,
    minimum_required_length: usize,
    buffer: *mut wdk_sys::PVOID,
    length: *mut usize,
) -> i32 {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveInputBuffer,
            request,
            minimum_required_length,
            buffer,
            length
        )
    }
}

pub fn WdfRequestRetrieveOutputBuffer(
    request: wdk_sys::WDFREQUEST,
    minimum_required_length: usize,
    buffer: *mut wdk_sys::PVOID,
    length: *mut usize,
) -> i32 {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveOutputBuffer,
            request,
            minimum_required_length,
            buffer,
            length
        )
    }
}

pub fn WdfRequestGetFileObject(request: wdk_sys::WDFREQUEST) -> wdk_sys::WDFFILEOBJECT {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfRequestGetFileObject, request) }
}

pub fn WdfRequestGetParameters(
    request: wdk_sys::WDFREQUEST,
    params: wdk_sys::PWDF_REQUEST_PARAMETERS,
) {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfRequestGetParameters, request, params) }
}

pub fn WdfDeviceEnqueueRequest(device: wdk_sys::WDFDEVICE, request: wdk_sys::WDFREQUEST) -> i32 {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfDeviceEnqueueRequest, device, request) }
}

pub fn WdfRequestForwardToIoQueue(
    request: wdk_sys::WDFREQUEST,
    queue: wdk_sys::WDFQUEUE,
) -> NTSTATUS {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(WdfRequestForwardToIoQueue, request, queue)
    }
}

pub fn WdfIoQueueRetrieveNextRequest(
    queue: wdk_sys::WDFQUEUE,
    out_request: *mut wdk_sys::WDFREQUEST,
) -> NTSTATUS {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfIoQueueRetrieveNextRequest,
            queue,
            out_request
        )
    }
}

pub fn WdfIoQueuePurge(
    queue: wdk_sys::WDFQUEUE,
    purge_complete: wdk_sys::PFN_WDF_IO_QUEUE_STATE,
    context: wdk_sys::WDFCONTEXT,
) {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(WdfIoQueuePurge, queue, purge_complete, context)
    }
}

pub fn WdfRequestComplete(request: wdk_sys::WDFREQUEST, status: i32) {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfRequestComplete, request, status) }
}

pub fn WdfRequestCompleteWithInformation(
    request: wdk_sys::WDFREQUEST,
    status: i32,
    information: wdk_sys::ULONG_PTR,
) {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfRequestCompleteWithInformation,
            request,
            status,
            information
        )
    }
}

pub fn WdfDeviceWdmGetDeviceObject(device: wdk_sys::WDFDEVICE) -> wdk_sys::PDEVICE_OBJECT {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfDeviceWdmGetDeviceObject, device) }
}

pub fn WdfRequestMarkCancelableEx(
    request: wdk_sys::WDFREQUEST,
    evt_request_cancel: wdk_sys::PFN_WDF_REQUEST_CANCEL,
) -> NTSTATUS {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfRequestMarkCancelableEx,
            request,
            evt_request_cancel
        )
    }
}

pub fn WdfRequestUnmarkCancelable(request: wdk_sys::WDFREQUEST) -> NTSTATUS {
    unsafe { wdk_sys::call_unsafe_wdf_function_binding!(WdfRequestUnmarkCancelable, request) }
}

pub fn WdfObjectGetTypedContextWorker(
    handle: wdk_sys::WDFOBJECT,
    type_info: wdk_sys::PCWDF_OBJECT_CONTEXT_TYPE_INFO,
) -> wdk_sys::PVOID {
    unsafe {
        wdk_sys::call_unsafe_wdf_function_binding!(
            WdfObjectGetTypedContextWorker,
            handle,
            type_info
        )
    }
}

/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::wdk_ext::wdf_wrapper::*;
use crate::{file, log};
use alloc::vec::Vec;
use core::ptr::null_mut;
use wdk_sys::{
    FILE_DEVICE_NETWORK, NTSTATUS, NT_SUCCESS, PCUNICODE_STRING, PDRIVER_OBJECT,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, UNICODE_STRING, WDFDEVICE, WDFDRIVER,
    WDF_DRIVER_CONFIG,
};

/// Driver entry point
///
/// This is the main entry point for the driver. It initializes the WDF driver object
/// and creates the main control device for user-space communication.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    log!("DriverEntry: Starting initialization");

    // Copy registry path globally
    if !registry_path.is_null() {
        unsafe {
            let len = ((*registry_path).Length / 2) as usize;
            let mut buf = alloc::vec::Vec::with_capacity(len + 1);
            core::ptr::copy_nonoverlapping((*registry_path).Buffer, buf.as_mut_ptr(), len);
            buf.set_len(len);
            buf.push(0); // Null terminator
            crate::set_global_registry_path(buf);
        }
    }

    crate::set_global_driver_object(driver);

    // 1. Initialize WDF driver
    let (driver_handle, status) = create_driver_object(driver, registry_path);
    if !NT_SUCCESS(status) {
        log!(
            "DriverEntry: create_driver_object failed with status {:#010X}",
            status
        );
        return status;
    }

    // 2. Create the control device
    let (_wdf_device, status) =
        create_control_device(driver_handle, crate::DEVICE_NAME, crate::DEVICE_DOS_PATH);
    if !NT_SUCCESS(status) {
        log!(
            "DriverEntry: create_control_device failed with status {:#010X}",
            status
        );
        return status;
    }

    log!("DriverEntry: Successfully initialized");
    status
}

/// Helper function to create a UNICODE_STRING from a Rust string slice.
/// Returns both the UNICODE_STRING and the backing Vec<u16> to ensure the
/// buffer outlives the UNICODE_STRING usage in the framework.
fn init_unicode_string(s: &str) -> (UNICODE_STRING, Vec<u16>) {
    let utf16_string: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
    let mut unicode_string = UNICODE_STRING::default();
    unsafe {
        wdk_sys::ntddk::RtlInitUnicodeString(&mut unicode_string, utf16_string.as_ptr());
    }
    (unicode_string, utf16_string)
}

/// Initializes the WDF driver object.
fn create_driver_object(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> (WDFDRIVER, NTSTATUS) {
    let mut driver_config = WDF_DRIVER_CONFIG {
        Size: size_of::<WDF_DRIVER_CONFIG>() as wdk_sys::ULONG,
        DriverInitFlags: wdk_sys::_WDF_DRIVER_INIT_FLAGS::WdfDriverInitNonPnpDriver as u32,
        EvtDriverUnload: Some(driver_unload),
        ..WDF_DRIVER_CONFIG::default()
    };

    let mut driver_handle: WDFDRIVER = null_mut();
    let status = WdfDriverCreate(
        driver,
        registry_path,
        wdk_sys::WDF_NO_OBJECT_ATTRIBUTES,
        &mut driver_config,
        &mut driver_handle,
    );

    (driver_handle, status)
}

/// Creates and configures the WDF control device.
fn create_control_device(
    driver_handle: WDFDRIVER,
    device_name_str: &str,
    dos_device_path_str: &str,
) -> (WDFDEVICE, NTSTATUS) {
    // 1. Allocate Device Init
    let mut device_init = allocate_device_init(driver_handle);
    if device_init.is_null() {
        return (null_mut(), STATUS_INSUFFICIENT_RESOURCES);
    }

    // 2. Set Device Name
    let (device_name, _device_name_buf) = init_unicode_string(device_name_str);
    let mut status = WdfDeviceInitAssignName(device_init, &device_name);
    if !NT_SUCCESS(status) {
        log!("WdfDeviceInitAssignName failed: {:#010X}", status);
        WdfDeviceInitFree(device_init);
        return (null_mut(), status);
    }

    // 3. Configure File Object and Callbacks
    configure_device_callbacks(device_init);

    // 4. Create the Device Object
    let mut device: WDFDEVICE = null_mut();
    let mut obj_attrs = wdk_sys::WDF_OBJECT_ATTRIBUTES {
        Size: size_of::<wdk_sys::WDF_OBJECT_ATTRIBUTES>() as wdk_sys::ULONG,
        ExecutionLevel: wdk_sys::_WDF_EXECUTION_LEVEL::WdfExecutionLevelInheritFromParent,
        SynchronizationScope:
            wdk_sys::_WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeInheritFromParent,
        ..wdk_sys::WDF_OBJECT_ATTRIBUTES::default()
    };

    status = WdfDeviceCreate(&mut device_init, &mut obj_attrs, &mut device);
    if !NT_SUCCESS(status) {
        log!("WdfDeviceCreate failed: {:#010X}", status);
        // device_init must be freed if WdfDeviceCreate fails
        WdfDeviceInitFree(device_init);
        return (null_mut(), status);
    }

    // 5. Create Symbolic Link
    let (dos_device_path, _dos_path_buf) = init_unicode_string(dos_device_path_str);
    status = WdfDeviceCreateSymbolicLink(device, &dos_device_path);
    if !NT_SUCCESS(status) {
        log!("WdfDeviceCreateSymbolicLink failed: {:#010X}", status);
        // Framework cleans up the device upon DriverEntry failure since it's linked
        return (null_mut(), status);
    }

    // 6. Create I/O Queue
    status = create_io_queue(device);
    if !NT_SUCCESS(status) {
        log!("create_io_queue failed: {:#010X}", status);
        return (null_mut(), status);
    }

    // 7. Finish Initializing
    WdfControlFinishInitializing(device);

    (device, STATUS_SUCCESS)
}

/// Allocates the WDFDEVICE_INIT structure for a control device.
fn allocate_device_init(driver_handle: WDFDRIVER) -> wdk_sys::PWDFDEVICE_INIT {
    // SDDL definition for: "System: All Access, Admin: All Access"
    const SDDL_ADMIN_ALL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    let (sddl_string, _sddl_buf) = init_unicode_string(SDDL_ADMIN_ALL);

    let device_init = WdfControlDeviceInitAllocate(driver_handle, &sddl_string);
    if device_init.is_null() {
        log!("WdfControlDeviceInitAllocate failed");
        return null_mut();
    }

    // Set device type and I/O type
    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetIoType(device_init, wdk_sys::_WDF_DEVICE_IO_TYPE::WdfDeviceIoDirect);

    device_init
}

/// Configures the file object callbacks and object attributes.
fn configure_device_callbacks(device_init: wdk_sys::PWDFDEVICE_INIT) {
    let mut file_config = wdk_sys::WDF_FILEOBJECT_CONFIG {
        Size: size_of::<wdk_sys::WDF_FILEOBJECT_CONFIG>() as wdk_sys::ULONG,
        EvtDeviceFileCreate: Some(file::file_create),
        EvtFileClose: Some(file::file_close),
        EvtFileCleanup: Some(file::file_cleanup),
        FileObjectClass: wdk_sys::_WDF_FILEOBJECT_CLASS::WdfFileObjectWdfCannotUseFsContexts,
        AutoForwardCleanupClose: wdk_sys::_WDF_TRI_STATE::WdfUseDefault,
    };

    let mut obj_attrs = wdk_sys::WDF_OBJECT_ATTRIBUTES {
        Size: size_of::<wdk_sys::WDF_OBJECT_ATTRIBUTES>() as wdk_sys::ULONG,
        ExecutionLevel: wdk_sys::_WDF_EXECUTION_LEVEL::WdfExecutionLevelInheritFromParent,
        SynchronizationScope:
            wdk_sys::_WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeInheritFromParent,
        EvtDestroyCallback: Some(file::file_destroy),
        // Embed one pointer-sized slot per file object for the Context pointer.
        ContextTypeInfo: unsafe { core::ptr::addr_of!(file::FILE_CTX_TYPE) },
        ..Default::default()
    };

    WdfDeviceInitSetFileObjectConfig(device_init, &mut file_config, &mut obj_attrs);
    WdfDeviceInitSetIoInCallerContextCallback(device_init, Some(file::io_in_caller_context));
}

/// Creates the I/O queue for the control device.
fn create_io_queue(device: WDFDEVICE) -> NTSTATUS {
    let mut queue_config = wdk_sys::WDF_IO_QUEUE_CONFIG {
        Size: size_of::<wdk_sys::WDF_IO_QUEUE_CONFIG>() as u32,
        PowerManaged: wdk_sys::_WDF_TRI_STATE::WdfUseDefault,
        DefaultQueue: 1, // 1 represents TRUE in WDF configuration
        DispatchType: wdk_sys::_WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchParallel,
        EvtIoDeviceControl: Some(file::ioctl_callback),
        ..wdk_sys::WDF_IO_QUEUE_CONFIG::default()
    };

    unsafe {
        queue_config.Settings.Parallel.NumberOfPresentedRequests = u32::MAX;
    }

    let mut queue_attrs = wdk_sys::WDF_OBJECT_ATTRIBUTES {
        Size: size_of::<wdk_sys::WDF_OBJECT_ATTRIBUTES>() as u32,
        ExecutionLevel: wdk_sys::_WDF_EXECUTION_LEVEL::WdfExecutionLevelPassive,
        SynchronizationScope: wdk_sys::_WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeNone,
        ..wdk_sys::WDF_OBJECT_ATTRIBUTES::default()
    };

    let mut queue: wdk_sys::WDFQUEUE = null_mut();
    WdfIoQueueCreate(device, &mut queue_config, &mut queue_attrs, &mut queue)
}

/// Driver unload callback.
///
/// Called by the framework when the driver is being unloaded.
unsafe extern "C" fn driver_unload(_driver: WDFDRIVER) {
    log!("DriverUnload");
}

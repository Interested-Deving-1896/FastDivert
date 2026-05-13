/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::ioctl_code::{
    DivertIoctlInitialize, DivertIoctlMMapRequest, DivertIoctlMMapResponse, DivertIoctlStartup,
    IOCTL_INITIALIZE, IOCTL_MAP_MM, IOCTL_STARTUP,
};
use std::ffi::c_void;
use windows::Win32::System::IO::DeviceIoControl;

pub fn initialize(
    device_handle: windows::Win32::Foundation::HANDLE,
    layer: u32,
    priority: u32,
    flags: u64,
) -> Result<(), windows::core::Error> {
    let mut bytes_returned = 0u32;
    let init_params = DivertIoctlInitialize {
        layer,
        priority,
        flags,
    };

    let response = crate::ioctl_code::IoctlInitializeResponse::default();
    unsafe {
        DeviceIoControl(
            device_handle,
            IOCTL_INITIALIZE,
            Some(&init_params as *const _ as *mut _),
            std::mem::size_of::<DivertIoctlInitialize>() as u32,
            Some(&response as *const _ as *mut _),
            size_of::<crate::ioctl_code::IoctlInitializeResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )
        .expect("Failed to initialize");
    }
    Ok(())
}

pub fn startup(
    device_handle: windows::Win32::Foundation::HANDLE,
) -> Result<(), windows::core::Error> {
    // 1. Send IOCTL_STARTUP to initialize RingBuffer context and WFP callouts in the kernel
    let startup_params = DivertIoctlStartup { flags: 0 };
    let mut bytes_returned = 0u32;
    unsafe {
        DeviceIoControl(
            device_handle,
            IOCTL_STARTUP,
            Some(&startup_params as *const _ as *mut _),
            std::mem::size_of::<DivertIoctlStartup>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
        .expect("Failed to startup");
    }

    Ok(())
}
pub fn map_rb(
    handle: windows::Win32::Foundation::HANDLE,
    req: crate::ioctl_code::DivertIoctlMMapRequest,
) -> Result<DivertIoctlMMapResponse, windows::core::Error> {
    unsafe {
        let mut bytes_returned = 0u32;

        let mut response = DivertIoctlMMapResponse::default();

        DeviceIoControl(
            handle,
            IOCTL_MAP_MM,
            Some(&req as *const _ as *mut c_void),
            size_of::<DivertIoctlMMapRequest>() as u32,
            Some(&mut response as *mut _ as *mut c_void),
            size_of::<DivertIoctlMMapResponse>() as u32,
            Some(&mut bytes_returned),
            None,
        )?;
        Ok(response)
    }
}

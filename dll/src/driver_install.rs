/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{Error, PCWSTR};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SERVICE_EXISTS, GENERIC_READ, GENERIC_WRITE,
    HANDLE, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, StartServiceW, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
    SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
    SERVICE_STATUS,
};

pub fn open_or_install_driver(name: &str, driver_path: &str, no_install: bool) -> Result<HANDLE> {
    match open_driver(name) {
        Ok(h) => Ok(h),
        Err(e) => {
            let code = e.code();
            // ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND
            if code == ERROR_FILE_NOT_FOUND.into()
                || code == ERROR_PATH_NOT_FOUND.into()
            {
                if no_install {
                    return Err(anyhow::Error::from(e).context(format!("Failed to open device handle for driver: \\\\.\\{}", name)));
                }
                install_driver(name, driver_path)?;
                return open_driver(name)
                    .map_err(|e| anyhow::Error::from(e).context(format!("Failed to open device handle for driver: \\\\.\\{}", name)));
            }
            Err(anyhow::Error::from(e).context(format!("Failed to open device handle for driver: \\\\.\\{}", name)))
        }
    }
}

pub fn open_driver(name: &str) -> std::result::Result<HANDLE, Error> {
    let full_name = format!(r"\\.\{}", name);
    let wide_name: Vec<u16> = OsStr::new(&full_name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        CreateFileW(
            PCWSTR(wide_name.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None,
        )
    }
}

pub fn install_driver(name: &str, path: &str) -> Result<()> {
    let wide_name: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
    let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();

    unsafe {
        let sc_manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
            .context("Failed to open Service Control Manager")?;

        let service = match CreateServiceW(
            sc_manager,
            PCWSTR(wide_name.as_ptr()),
            PCWSTR(wide_name.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(wide_path.as_ptr()),
            None,
            None,
            None,
            None,
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                if e.code() == ERROR_SERVICE_EXISTS.into() {
                    OpenServiceW(sc_manager, PCWSTR(wide_name.as_ptr()), SERVICE_ALL_ACCESS)
                        .with_context(|| format!("Failed to open existing service: {}", name))?
                } else {
                    let _ = CloseServiceHandle(sc_manager);
                    return Err(e).with_context(|| format!("Failed to create service: {}", name));
                }
            }
        };

        let mut result = StartServiceW(service, None);

        if let Err(ref e) = result {
            // ERROR_SERVICE_ALREADY_RUNNING
            if e.code().0 == (0x80070420u32 as i32)
                || e.code().0 == WIN32_ERROR(1056).to_hresult().0
            {
                result = Ok(());
            }
        }

        let final_result = result.with_context(|| format!("Failed to start service: {}", name));

        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(sc_manager);

        final_result?;
        Ok(())
    }
}

pub fn uninstall_driver(name: &str) -> Result<()> {
    let wide_name: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();

    unsafe {
        let sc_manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
            .context("Failed to open Service Control Manager for uninstallation")?;
        let service = OpenServiceW(sc_manager, PCWSTR(wide_name.as_ptr()), SERVICE_ALL_ACCESS)
            .with_context(|| format!("Failed to open service for uninstallation: {}", name))?;

        let mut status = SERVICE_STATUS::default();
        let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
        let result =
            DeleteService(service).with_context(|| format!("Failed to delete service: {}", name));

        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(sc_manager);

        result?;
        Ok(())
    }
}

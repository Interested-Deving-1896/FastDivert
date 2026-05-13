/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

//! Context structure and management for file objects

extern crate alloc;
use alloc::boxed::Box;
use core::ptr::null_mut;

use crate::network::context::NetworkContext;
use crate::wdk_ext::wdf_wrapper::WdfIoQueueCreate;
use wdk_sys::{NTSTATUS, ULONG};
use crate::log;

/// Context state enum
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum ContextState {
    Opening = 0xA0,
    Open = 0xB1,
    Closing = 0xC2,
    #[default]
    Closed = 0xD3,
}

/// Context structure for file objects
/// Each open handle to the device has its own context
#[repr(C)]
pub struct Context {
    pub state: ContextState,
    pub lock: wdk::wdf::SpinLock,

    pub device: wdk_sys::WDFDEVICE,
    pub object: wdk_sys::WDFFILEOBJECT,

    // Manual queue to hold pending RECV requests
    pub recv_queue: wdk_sys::WDFQUEUE,

    // from user request
    pub layer: u32,
    pub priority: u32,
    pub flags: u64,

    pub network_ctx: NetworkContext,
}

impl Context {
    /// Create a new context
    pub fn new(
        device: wdk_sys::WDFDEVICE,
        object: wdk_sys::WDFFILEOBJECT,
    ) -> Result<Box<Context>, NTSTATUS> {
        //Initialize spinlock
        let lock = wdk::wdf::SpinLock::create(&mut wdk_sys::WDF_OBJECT_ATTRIBUTES {
            Size: size_of::<wdk_sys::WDF_OBJECT_ATTRIBUTES>() as ULONG,
            ExecutionLevel: wdk_sys::_WDF_EXECUTION_LEVEL::WdfExecutionLevelInheritFromParent,
            SynchronizationScope:
                wdk_sys::_WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeInheritFromParent,
            ..Default::default()
        })?;

        // Create a manual I/O queue to hold pending RECV requests
        // Initialize as manual queue. WDF_IO_QUEUE_CONFIG_INIT is an inline macro in C,
        // so we manually replicate its behavior here.
        let mut queue_config = wdk_sys::WDF_IO_QUEUE_CONFIG {
            Size: size_of::<wdk_sys::WDF_IO_QUEUE_CONFIG>() as ULONG,
            DispatchType: wdk_sys::_WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchManual,
            PowerManaged: wdk_sys::_WDF_TRI_STATE::WdfFalse,
            AllowZeroLengthRequests: 0, // WdfFalse
            DefaultQueue: 0, // WdfFalse
            ..Default::default()
        };

        // We want the queue's parent to be the file object, so it gets cleaned up automatically
        let mut queue_attrs = wdk_sys::WDF_OBJECT_ATTRIBUTES {
            Size: size_of::<wdk_sys::WDF_OBJECT_ATTRIBUTES>() as ULONG,
            ParentObject: object as wdk_sys::WDFOBJECT,
            ExecutionLevel: wdk_sys::_WDF_EXECUTION_LEVEL::WdfExecutionLevelPassive,
            SynchronizationScope: wdk_sys::_WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeNone,
            ..Default::default()
        };

        let mut recv_queue: wdk_sys::WDFQUEUE = null_mut();
        let status = WdfIoQueueCreate(device, &mut queue_config, &mut queue_attrs, &mut recv_queue);

        if !wdk::nt_success(status) {
            log!("Context::new: failed to create recv queue: {:#010X}", status);
            return Err(status);
        }

        let mut context: Context = Context {
            state: Default::default(),
            lock,
            device,
            object,
            recv_queue,
            layer: 0,
            priority: 0,
            flags: 0,
            network_ctx: NetworkContext::new()?,
        };

        Ok(Box::new(context))
    }

    /// Initialize the context (called during file create)
    pub fn initialize(&mut self) -> Result<(), NTSTATUS> {
        // Initialize network context
        self.network_ctx.initialize()?;

        // set state to Opening
        self.set_state(ContextState::Open);

        Ok(())
    }

    /// Acquire context lock
    pub fn lock(&mut self) {
        unsafe {
            self.lock.acquire();
        }
    }

    /// Release context lock
    pub fn unlock(&mut self) {
        unsafe {
            self.lock.release();
        }
    }

    /// Check if context is open
    pub fn is_open(&self) -> bool {
        self.state == ContextState::Open
    }

    /// Check if context is closing or closed
    pub fn is_closing(&self) -> bool {
        matches!(self.state, ContextState::Closing | ContextState::Closed)
    }

    /// Set context state
    pub fn set_state(&mut self, new_state: ContextState) {
        self.state = new_state;
    }
}

impl Drop for Context {
    fn drop(&mut self) {}
}

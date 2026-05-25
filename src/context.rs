//! Context structure and management for file objects

extern crate alloc;
use alloc::boxed::Box;
use core::ptr::null_mut;

use crate::network::module::NetworkModule;
use crate::file_monitor::file_module::FileModule;
use crate::wdk_ext::wdf_wrapper::WdfIoQueueCreate;
use wdk_sys::{NTSTATUS, ULONG};
use crate::log;

/// Polymorphic context representing either a Network or File module.
pub enum ModuleContext {
    Network(Box<NetworkModule>),
    File(Box<FileModule>),
}

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

/// Context structure for file objects.
/// Each open handle to the device has its own general Context.
#[repr(C)]
pub struct Context {
    pub state: ContextState,
    pub lock: wdk::wdf::SpinLock,

    pub device: wdk_sys::WDFDEVICE,
    pub object: wdk_sys::WDFFILEOBJECT,

    // Manual queue to hold pending RECV requests
    pub recv_queue: wdk_sys::WDFQUEUE,

    // General configuration from user-space initialize request
    pub layer: u32,
    pub priority: u32,
    pub flags: u64,

    // Polymorphic active module context
    pub module: Option<ModuleContext>,
}

impl Context {
    /// Create a new context
    pub fn new(
        device: wdk_sys::WDFDEVICE,
        object: wdk_sys::WDFFILEOBJECT,
    ) -> Result<Box<Context>, NTSTATUS> {
        // Initialize spinlock
        let lock = wdk::wdf::SpinLock::create(&mut wdk_sys::WDF_OBJECT_ATTRIBUTES {
            Size: size_of::<wdk_sys::WDF_OBJECT_ATTRIBUTES>() as ULONG,
            ExecutionLevel: wdk_sys::_WDF_EXECUTION_LEVEL::WdfExecutionLevelInheritFromParent,
            SynchronizationScope:
                wdk_sys::_WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeInheritFromParent,
            ..Default::default()
        })?;

        // Create a manual I/O queue to hold pending RECV requests
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

        let context: Context = Context {
            state: Default::default(),
            lock,
            device,
            object,
            recv_queue,
            layer: 0,
            priority: 0,
            flags: 0,
            module: None,
        };

        Ok(Box::new(context))
    }

    /// Initialize the context state to Open (called during file create/initialization)
    pub fn initialize(&mut self) -> Result<(), NTSTATUS> {
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

    /// Safe helper to get a pointer to the active NetworkContext if this context is a network module.
    pub fn get_network_ctx_ptr(&self) -> *mut crate::network::context::NetworkContext {
        if let Some(ModuleContext::Network(net_module)) = &self.module {
            return &net_module.network_ctx as *const _ as *mut _;
        }
        core::ptr::null_mut()
    }

    /// Safe helper to get a pointer to the active NetworkModule if this context is a network module.
    pub fn get_network_module_ptr(&self) -> *mut crate::network::module::NetworkModule {
        if let Some(ModuleContext::Network(net_module)) = &self.module {
            return &**net_module as *const _ as *mut _;
        }
        core::ptr::null_mut()
    }
}

impl Drop for Context {
    fn drop(&mut self) {}
}
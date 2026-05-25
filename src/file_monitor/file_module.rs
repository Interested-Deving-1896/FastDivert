//! File monitoring driver module implementation

extern crate alloc;
use alloc::boxed::Box;
use core::ptr::null_mut;
use core::mem::size_of;
use wdk_sys::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS, WDFREQUEST,
};

use crate::context::Context;
use crate::file_monitor::minifilter::{
    get_minifilter_registration, init_transaction_tracker, ACTIVE_FILE_MODULE, TRANSACTION_TRACKER,
};
use crate::ioctl_internal::{FileDecision, FileEvent, FileModuleConfig, IoctlMMapResponse};
use crate::log;

use crate::ringbuffer::{PerCpuRingBuffer, RecordHeader};
use crate::wdk_ext::flt::{FltRegisterFilter, FltStartFiltering, FltUnregisterFilter, PFLT_FILTER};

/// Helper to provision the Instances registry keys dynamically under our service node
unsafe fn provision_registry_keys(registry_path: &[u16]) -> Result<(), NTSTATUS> {
    if registry_path.is_empty() {
        return Err(wdk_sys::STATUS_UNSUCCESSFUL);
    }

    let mut base_str = wdk_sys::UNICODE_STRING::default();
    // registry_path has a null terminator, so length is len - 1
    let registry_path_len_bytes = ((registry_path.len() - 1) * 2) as u16;
    base_str.Length = registry_path_len_bytes;
    base_str.MaximumLength = (registry_path.len() * 2) as u16;
    base_str.Buffer = registry_path.as_ptr() as *mut u16;

    let mut obj_attrs = wdk_sys::OBJECT_ATTRIBUTES::default();
    obj_attrs.Length = core::mem::size_of::<wdk_sys::OBJECT_ATTRIBUTES>() as u32;
    obj_attrs.ObjectName = &mut base_str;
    obj_attrs.Attributes = wdk_sys::OBJ_CASE_INSENSITIVE | wdk_sys::OBJ_KERNEL_HANDLE;

    let mut base_handle: wdk_sys::HANDLE = null_mut();
    let mut disposition = 0;
    let mut status = unsafe {
        wdk_sys::ntddk::ZwCreateKey(
            &mut base_handle,
            wdk_sys::KEY_ALL_ACCESS,
            &mut obj_attrs,
            0,
            null_mut(),
            wdk_sys::REG_OPTION_NON_VOLATILE,
            &mut disposition,
        )
    };
    if !wdk::nt_success(status) {
        log!(
            "provision_registry_keys: ZwCreateKey on base path failed: {:#010X}",
            status
        );
        return Err(status);
    }

    let mut instances_name = wdk_sys::UNICODE_STRING::default();
    let instances_u16: alloc::vec::Vec<u16> = "Instances".encode_utf16().collect();
    instances_name.Length = (instances_u16.len() * 2) as u16;
    instances_name.MaximumLength = (instances_u16.len() * 2) as u16;
    instances_name.Buffer = instances_u16.as_ptr() as *mut u16;

    let mut inst_obj_attrs = wdk_sys::OBJECT_ATTRIBUTES::default();
    inst_obj_attrs.Length = core::mem::size_of::<wdk_sys::OBJECT_ATTRIBUTES>() as u32;
    inst_obj_attrs.ObjectName = &mut instances_name;
    inst_obj_attrs.RootDirectory = base_handle;
    inst_obj_attrs.Attributes = wdk_sys::OBJ_CASE_INSENSITIVE | wdk_sys::OBJ_KERNEL_HANDLE;

    let mut instances_handle: wdk_sys::HANDLE = null_mut();
    status = unsafe {
        wdk_sys::ntddk::ZwCreateKey(
            &mut instances_handle,
            wdk_sys::KEY_ALL_ACCESS,
            &mut inst_obj_attrs,
            0,
            null_mut(),
            wdk_sys::REG_OPTION_NON_VOLATILE,
            &mut disposition,
        )
    };
    if !wdk::nt_success(status) {
        log!(
            "provision_registry_keys: ZwCreateKey for Instances failed: {:#010X}",
            status
        );
        unsafe {
            wdk_sys::ntddk::ZwClose(base_handle);
        }
        return Err(status);
    }

    let def_inst_u16: alloc::vec::Vec<u16> = "DefaultInstance".encode_utf16().collect();
    let mut def_inst_name = wdk_sys::UNICODE_STRING::default();
    def_inst_name.Length = (def_inst_u16.len() * 2) as u16;
    def_inst_name.MaximumLength = (def_inst_u16.len() * 2) as u16;
    def_inst_name.Buffer = def_inst_u16.as_ptr() as *mut u16;

    let def_val_u16: alloc::vec::Vec<u16> = "FastDivertInstance"
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    status = unsafe {
        wdk_sys::ntddk::ZwSetValueKey(
            instances_handle,
            &mut def_inst_name,
            0,
            wdk_sys::REG_SZ,
            def_val_u16.as_ptr() as *mut _,
            (def_val_u16.len() * 2) as u32,
        )
    };
    if !wdk::nt_success(status) {
        log!(
            "provision_registry_keys: ZwSetValueKey for DefaultInstance failed: {:#010X}",
            status
        );
        unsafe {
            wdk_sys::ntddk::ZwClose(instances_handle);
            wdk_sys::ntddk::ZwClose(base_handle);
        }
        return Err(status);
    }

    let mut subkey_name = wdk_sys::UNICODE_STRING::default();
    let subkey_u16: alloc::vec::Vec<u16> = "FastDivertInstance".encode_utf16().collect();
    subkey_name.Length = (subkey_u16.len() * 2) as u16;
    subkey_name.MaximumLength = (subkey_u16.len() * 2) as u16;
    subkey_name.Buffer = subkey_u16.as_ptr() as *mut u16;

    let mut sub_obj_attrs = wdk_sys::OBJECT_ATTRIBUTES::default();
    sub_obj_attrs.Length = core::mem::size_of::<wdk_sys::OBJECT_ATTRIBUTES>() as u32;
    sub_obj_attrs.ObjectName = &mut subkey_name;
    sub_obj_attrs.RootDirectory = instances_handle;
    sub_obj_attrs.Attributes = wdk_sys::OBJ_CASE_INSENSITIVE | wdk_sys::OBJ_KERNEL_HANDLE;

    let mut subkey_handle: wdk_sys::HANDLE = null_mut();
    status = unsafe {
        wdk_sys::ntddk::ZwCreateKey(
            &mut subkey_handle,
            wdk_sys::KEY_ALL_ACCESS,
            &mut sub_obj_attrs,
            0,
            null_mut(),
            wdk_sys::REG_OPTION_NON_VOLATILE,
            &mut disposition,
        )
    };
    if !wdk::nt_success(status) {
        log!(
            "provision_registry_keys: ZwCreateKey for FastDivertInstance failed: {:#010X}",
            status
        );
        unsafe {
            wdk_sys::ntddk::ZwClose(instances_handle);
            wdk_sys::ntddk::ZwClose(base_handle);
        }
        return Err(status);
    }

    let alt_name_u16: alloc::vec::Vec<u16> = "Altitude".encode_utf16().collect();
    let mut alt_name = wdk_sys::UNICODE_STRING::default();
    alt_name.Length = (alt_name_u16.len() * 2) as u16;
    alt_name.MaximumLength = (alt_name_u16.len() * 2) as u16;
    alt_name.Buffer = alt_name_u16.as_ptr() as *mut u16;

    let alt_val_u16: alloc::vec::Vec<u16> =
        "385000".encode_utf16().chain(core::iter::once(0)).collect();
    status = unsafe {
        wdk_sys::ntddk::ZwSetValueKey(
            subkey_handle,
            &mut alt_name,
            0,
            wdk_sys::REG_SZ,
            alt_val_u16.as_ptr() as *mut _,
            (alt_val_u16.len() * 2) as u32,
        )
    };
    if !wdk::nt_success(status) {
        log!(
            "provision_registry_keys: ZwSetValueKey for Altitude failed: {:#010X}",
            status
        );
        unsafe {
            wdk_sys::ntddk::ZwClose(subkey_handle);
            wdk_sys::ntddk::ZwClose(instances_handle);
            wdk_sys::ntddk::ZwClose(base_handle);
        }
        return Err(status);
    }

    let flags_name_u16: alloc::vec::Vec<u16> = "Flags".encode_utf16().collect();
    let mut flags_name = wdk_sys::UNICODE_STRING::default();
    flags_name.Length = (flags_name_u16.len() * 2) as u16;
    flags_name.MaximumLength = (flags_name_u16.len() * 2) as u16;
    flags_name.Buffer = flags_name_u16.as_ptr() as *mut u16;

    let flags_val: u32 = 0;
    status = unsafe{
        wdk_sys::ntddk::ZwSetValueKey(
            subkey_handle,
            &mut flags_name,
            0,
            wdk_sys::REG_DWORD,
            &flags_val as *const u32 as *mut _,
            core::mem::size_of::<u32>() as u32,
        )
    };
    if !wdk::nt_success(status) {
        log!(
            "provision_registry_keys: ZwSetValueKey for Flags failed: {:#010X}",
            status
        );
    }

    unsafe {
        wdk_sys::ntddk::ZwClose(subkey_handle);
        wdk_sys::ntddk::ZwClose(instances_handle);
        wdk_sys::ntddk::ZwClose(base_handle);
    }
    Ok(())
}

pub struct FileModule {
    pub config: Box<FileModuleConfig>,
    pub ring_buffer: Option<Box<PerCpuRingBuffer>>,
    pub filter_handle: PFLT_FILTER,
    pub exempt_pid: u32,
}

unsafe impl Send for FileModule {}
unsafe impl Sync for FileModule {}

impl FileModule {
    /// Create a new FileModule
    pub fn new() -> Result<Self, NTSTATUS> {
        // Allocate 2MB SPSC/MPSC PerCpu Ring Buffer for passing file IO events to user-space
        let rb = PerCpuRingBuffer::allocate(2 * 1024 * 1024, 1)?;

        // Heap-allocate FileModuleConfig zero-initialized to completely bypass stack temporaries.
        let mut config_box = unsafe {
            let layout = core::alloc::Layout::new::<FileModuleConfig>();
            let ptr = alloc::alloc::alloc_zeroed(layout) as *mut FileModuleConfig;
            if ptr.is_null() {
                return Err(wdk_sys::STATUS_INSUFFICIENT_RESOURCES);
            }
            Box::from_raw(ptr)
        };

        // Initialize the default parameters on the heap box
        config_box.timeout_ms = 3000;
        config_box.default_action = 1; // Allow
        config_box.rule_count = 0;

        Ok(Self {
            config: config_box,
            ring_buffer: Some(rb),
            filter_handle: null_mut(),
            exempt_pid: 0,
        })
    }

    /// Serializes and pushes a file event record into the ring buffer and returns the start tail offset
    pub fn push_event(
        &self,
        transaction_id: u64,
        process_id: u32,
        op_code: u32,
        path: &[u16],
    ) -> Result<usize, NTSTATUS> {
        let event = FileEvent {
            transaction_id,
            process_id,
            op_code,
            path_len: path.len() as u32,
            decision: 1, // Default Allow
            redirect_path_len: 0,
            redirect_path: [0u16; crate::ioctl_internal::MAX_RULE_PATH_LEN],
        };

        let event_len = core::mem::size_of::<FileEvent>();
        let path_bytes_len = path.len() * 2;
        let total_len = event_len + path_bytes_len;

        let header = RecordHeader {
            len: total_len as u32,
            _reserved: 0,
        };

        let total_rb_size = core::mem::size_of::<RecordHeader>() + total_len;

        if let Some(ref rb) = self.ring_buffer {
            rb.transaction(0, total_rb_size, |tx| {
                tx.push_slice(&header, unsafe {
                    core::slice::from_raw_parts(&event as *const FileEvent as *const u8, event_len)
                })?;
                tx.push_slice_only(unsafe {
                    core::slice::from_raw_parts(path.as_ptr() as *const u8, path_bytes_len)
                });
                Ok(tx.start_tail)
            })
        } else {
            Err(STATUS_INVALID_DEVICE_REQUEST)
        }
    }
}

impl FileModule {
    pub fn startup(&mut self, ctx_ptr: *mut Context, flags: u64) -> Result<(), NTSTATUS> {
        log!("FileModule::startup: registering Minifilter and initializing TransactionTracker");
        unsafe {
            let ctx = &mut *ctx_ptr;
            ctx.flags = flags;

            let initiator_pid = crate::wdk_ext::wdf_wrapper::WdfFileObjectGetInitiatorProcessId(ctx.object);
            self.exempt_pid = initiator_pid;
            log!("FileModule::startup: set initiator process PID {} as exempt", initiator_pid);

            // Provision registry keys programmatically so we are INF-less
            let registry_path = crate::get_global_registry_path();
            if let Err(status) = provision_registry_keys(registry_path) {
                return Err(status);
            }

            // Initialize the global synchronous transaction tracker
            init_transaction_tracker();

            // Store this as the active file module for minifilter callbacks
            ACTIVE_FILE_MODULE = self as *mut FileModule;

            // Register and start the minifilter
            let reg = get_minifilter_registration();
            let mut filter_h: PFLT_FILTER = null_mut();
            let driver_obj =
                crate::get_global_driver_object() as *mut crate::wdk_ext::flt::_DRIVER_OBJECT;

            let status = FltRegisterFilter(driver_obj, &reg, &mut filter_h);
            if !wdk::nt_success(status) {
                log!(
                    "FileModule::startup: FltRegisterFilter failed: {:#010X}",
                    status
                );
                ACTIVE_FILE_MODULE = null_mut();
                return Err(status);
            }

            self.filter_handle = filter_h;

            let start_status = FltStartFiltering(filter_h);
            if !wdk::nt_success(start_status) {
                log!(
                    "FileModule::startup: FltStartFiltering failed: {:#010X}",
                    start_status
                );
                FltUnregisterFilter(filter_h);
                self.filter_handle = null_mut();
                ACTIVE_FILE_MODULE = null_mut();
                return Err(start_status);
            }

            log!("FileModule::startup: Minifilter successfully registered and started!");
            Ok(())
        }
    }

    pub fn map_memory(&self) -> Result<IoctlMMapResponse, NTSTATUS> {
        unsafe {
            if let Some(ref rb) = self.ring_buffer {
                let (recv_header, recv_data) = match rb.map_to_user_space() {
                    Ok(map_result) => map_result,
                    Err(err) => {
                        log!("FileModule::map_memory: failed to map file ring buffer");
                        return Err(err);
                    }
                };

                Ok(IoctlMMapResponse {
                    max_cores: 1,
                    size: 2 * 1024 * 1024,
                    ring_buffer_header: recv_header,
                    ring_buffer_data: recv_data,
                    send_ring_buffer_header: null_mut(),
                    send_ring_buffer_data: null_mut(),
                })
            } else {
                Err(STATUS_INVALID_DEVICE_REQUEST)
            }
        }
    }

    pub fn arm_recv(&self, ctx_ptr: *mut Context) -> Result<(), NTSTATUS> {
        unsafe {
            if let Some(ref rb) = self.ring_buffer {
                rb.set_notify_callback(
                    Some(crate::network::module::packet_arrived_callback),
                    ctx_ptr as *mut core::ffi::c_void,
                );
                rb.set_watching();
                Ok(())
            } else {
                Err(STATUS_INVALID_DEVICE_REQUEST)
            }
        }
    }

    pub fn handle_send(
        &self,
        _ctx_ptr: *mut Context,
        request: WDFREQUEST,
        input_buffer_len: usize,
    ) -> NTSTATUS {
        unsafe {
            if input_buffer_len < size_of::<FileDecision>() {
                return STATUS_BUFFER_TOO_SMALL;
            }

            let mut input_ptr: wdk_sys::PVOID = null_mut();
            let mut input_len: usize = 0;
            let status = crate::wdk_ext::wdf_wrapper::WdfRequestRetrieveInputBuffer(
                request,
                size_of::<FileDecision>(),
                &mut input_ptr,
                &mut input_len,
            );

            if !wdk::nt_success(status) || input_ptr.is_null() {
                return status;
            }

            let decision = &*(input_ptr as *const FileDecision);

            let tracker_ptr = &raw mut TRANSACTION_TRACKER;
            if let Some(tracker) = unsafe { &mut *tracker_ptr } {
                let found = tracker.signal(decision);
                if found {
                    STATUS_SUCCESS
                } else {
                    log!(
                        "FileModule::handle_send: transaction ID {} not found",
                        decision.transaction_id
                    );
                    wdk_sys::STATUS_NOT_FOUND
                }
            } else {
                STATUS_INVALID_DEVICE_REQUEST
            }
        }
    }

    pub fn cleanup(&mut self, _ctx_ptr: *mut Context) {
        log!("FileModule::cleanup: tearing down file minifilter and deallocating SPSC ring buffer");
        unsafe {
            if !self.filter_handle.is_null() {
                FltUnregisterFilter(self.filter_handle);
                self.filter_handle = null_mut();
            }

            ACTIVE_FILE_MODULE = null_mut();

            if let Some(rb) = self.ring_buffer.take() {
                rb.set_notify_callback(None, null_mut());
                rb.clear_watching();
                // Ownership is taken, Box is automatically dropped and freed cleanly here
            }
        }
    }
}

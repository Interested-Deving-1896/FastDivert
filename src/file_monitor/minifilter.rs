//! Global Minifilter registration, callbacks, path matching, and synchronous transaction tracking

extern crate alloc;
use core::ptr::null_mut;
use wdk_sys::NTSTATUS;

use crate::ioctl_internal::{FileFilterRule, MAX_FILTER_RULES, MAX_RULE_PATH_LEN};
use crate::log;

// Import Filter Manager functions and structures from our generated bindings
use crate::wdk_ext::flt::*;

pub const FLT_PREOP_SUCCESS_NO_CALLBACK: FLT_PREOP_CALLBACK_STATUS =
    _FLT_PREOP_CALLBACK_STATUS_FLT_PREOP_SUCCESS_NO_CALLBACK;
pub const FLT_PREOP_COMPLETE: FLT_PREOP_CALLBACK_STATUS =
    _FLT_PREOP_CALLBACK_STATUS_FLT_PREOP_COMPLETE;

/// A pending file intercept transaction.
pub struct PendingTransaction {
    pub transaction_id: u64,
    pub event: wdk_sys::KEVENT,
    pub start_tail: usize, // The offset where its record resides in the ring buffer
}

/// Thread-safe registry that matches incoming decisions to suspended threads.
pub struct TransactionTracker {
    pub lock: wdk_sys::KSPIN_LOCK,
    pub transactions: alloc::vec::Vec<*mut PendingTransaction>,
}

impl TransactionTracker {
    /// Safely registers a pending transaction.
    pub unsafe fn add(&mut self, tx: *mut PendingTransaction) {
        let old_irql = unsafe {
            wdk_sys::ntddk::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!(self.lock))
        };
        self.transactions.push(tx);
        unsafe {
            wdk_sys::ntddk::KeReleaseSpinLock(core::ptr::addr_of_mut!(self.lock), old_irql);
        }
    }

    /// Safely removes a pending transaction.
    pub unsafe fn remove(&mut self, tx: *mut PendingTransaction) {
        let old_irql = unsafe {
            wdk_sys::ntddk::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!(self.lock))
        };
        if let Some(pos) = self.transactions.iter().position(|&x| x == tx) {
            self.transactions.remove(pos);
        }
        unsafe { wdk_sys::ntddk::KeReleaseSpinLock(core::ptr::addr_of_mut!(self.lock), old_irql) };
    }

    /// Matches a user-space decision to a blocked thread and signals the KEVENT.
    pub unsafe fn signal(&mut self, decision_struct: &crate::ioctl_internal::FileDecision) -> bool {
        let old_irql = unsafe {
            wdk_sys::ntddk::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!(self.lock))
        };
        let mut found = false;
        for &tx in &self.transactions {
            if unsafe { (*tx).transaction_id } == decision_struct.transaction_id {
                unsafe {
                    wdk_sys::ntddk::KeSetEvent(core::ptr::addr_of_mut!((*tx).event), 0, 0);
                }
                found = true;
                break;
            }
        }
        unsafe { wdk_sys::ntddk::KeReleaseSpinLock(core::ptr::addr_of_mut!(self.lock), old_irql) };
        found
    }
}

// Global static transaction tracker
pub static mut TRANSACTION_TRACKER: Option<TransactionTracker> = None;

// Global pointer to the active file module context
pub static mut ACTIVE_FILE_MODULE: *mut crate::file_monitor::file_module::FileModule = null_mut();

/// Initializes the global transaction tracker
pub unsafe fn init_transaction_tracker() {
    unsafe {
        let mut tracker = TransactionTracker {
            lock: 0,
            transactions: alloc::vec::Vec::new(),
        };
        // Explicitly initialize the spinlock via the standard Windows WDK API
        wdk_sys::ntddk::KeInitializeSpinLock(core::ptr::addr_of_mut!(tracker.lock));
        TRANSACTION_TRACKER = Some(tracker);
    }
}

/// Helper to convert a u16 wide char to ASCII lowercase (case-insensitive path matching helper).
#[inline(always)]
fn to_lower_u16(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + (b'a' as u16 - b'A' as u16)
    } else {
        c
    }
}

/// Checks if `path` has the given case-insensitive `prefix`.
pub fn matches_prefix_u16(path: &[u16], prefix: &[u16]) -> bool {
    if path.len() < prefix.len() {
        return false;
    }
    for i in 0..prefix.len() {
        if to_lower_u16(path[i]) != to_lower_u16(prefix[i]) {
            return false;
        }
    }
    true
}

/// Checks if `path` ends with the given case-insensitive `suffix`.
pub fn matches_suffix_u16(path: &[u16], suffix: &[u16]) -> bool {
    if path.len() < suffix.len() {
        return false;
    }
    let offset = path.len() - suffix.len();
    for i in 0..suffix.len() {
        if to_lower_u16(path[offset + i]) != to_lower_u16(suffix[i]) {
            return false;
        }
    }
    true
}

/// Checks if `path` matches the case-insensitive wildcard/glob `pattern`.
/// Supports '*' and '?' wildcards in a stack-safe non-recursive loop.
pub fn matches_glob_u16(path: &[u16], pattern: &[u16]) -> bool {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    let p_len = pattern.len();
    let t_len = path.len();

    while t_idx < t_len {
        if p_idx < p_len
            && (to_lower_u16(pattern[p_idx]) == to_lower_u16(path[t_idx])
                || pattern[p_idx] == b'?' as u16)
        {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_len && pattern[p_idx] == b'*' as u16 {
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(s_idx) = star_idx {
            p_idx = s_idx + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < p_len && pattern[p_idx] == b'*' as u16 {
        p_idx += 1;
    }

    p_idx == p_len
}

/// Retrieves the normalized absolute file path using Filter Manager.
pub unsafe fn get_file_path(
    data: *mut FLT_CALLBACK_DATA,
    format: u32,
    path_buf: &mut [u16],
) -> Result<usize, NTSTATUS> {
    if data.is_null() {
        return Err(wdk_sys::STATUS_INVALID_PARAMETER);
    }

    let mut name_info: *mut FLT_FILE_NAME_INFORMATION = null_mut();

    // Query file path with the specified format
    let status = unsafe {
        FltGetFileNameInformation(data, format | FLT_FILE_NAME_QUERY_DEFAULT, &mut name_info)
    };
    if !wdk::nt_success(status) {
        return Err(status);
    }

    let name = unsafe { &*name_info };
    if name.Name.Buffer.is_null() || name.Name.Length == 0 {
        unsafe {
            FltReleaseFileNameInformation(name_info);
        }
        return Ok(0);
    }

    let len = (name.Name.Length / 2) as usize;
    let len_to_copy = core::cmp::min(len, path_buf.len());

    unsafe {
        core::ptr::copy_nonoverlapping(name.Name.Buffer, path_buf.as_mut_ptr(), len_to_copy);
        FltReleaseFileNameInformation(name_info);
    }

    Ok(len_to_copy)
}

/// Global Minifilter Pre-Operation callback.
/// Captures file I/O operations and handles read-only monitoring or active interception.
pub unsafe extern "C" fn minifilter_pre_op(
    data: *mut FLT_CALLBACK_DATA,
    _pc_ctx: PCFLT_RELATED_OBJECTS,
    _completion_ctx: *mut *mut core::ffi::c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    if data.is_null() || unsafe { (*data).Iopb.is_null() } {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Completely ignore background system paging I/O to avoid deadlock/access violations
    let irp_flags = unsafe { (*(*data).Iopb).IrpFlags };
    if (irp_flags & (wdk_sys::IRP_PAGING_IO | wdk_sys::IRP_SYNCHRONOUS_PAGING_IO)) != 0 {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let file_module_ptr = unsafe { ACTIVE_FILE_MODULE };
    if file_module_ptr.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    let file_module = unsafe { &*file_module_ptr };

    let process_id = unsafe { wdk_sys::ntddk::PsGetCurrentProcessId() } as u32;
    if process_id == file_module.exempt_pid {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let major_function = unsafe { (*(*data).Iopb).MajorFunction } as u32;

    // Use opened name format for pre-create to avoid recursive metadata/security descriptor queries.
    // Use normalized name format for already opened files (write, set info).
    let format = if major_function == wdk_sys::IRP_MJ_CREATE as u32 {
        FLT_FILE_NAME_OPENED
    } else {
        FLT_FILE_NAME_NORMALIZED
    };

    // Resolve file path
    let mut path_buf = [0u16; 1024]; // Increase buffer size to accommodate longer paths
    let path_len = match unsafe { get_file_path(data, format, &mut path_buf) } {
        Ok(len) => len,
        Err(_) => return FLT_PREOP_SUCCESS_NO_CALLBACK,
    };
    if path_len == 0 {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    let path_slice = &path_buf[..path_len];

    // Evaluate matching filter rules (clamped to MAX_FILTER_RULES to guarantee memory safety)
    let mut matched_rule: Option<&FileFilterRule> = None;
    let rule_count = core::cmp::min(file_module.config.rule_count as usize, MAX_FILTER_RULES);
    for i in 0..rule_count {
        let rule = &file_module.config.rules[i];
        let op_flag = match major_function {
            wdk_sys::IRP_MJ_CREATE => 1,
            wdk_sys::IRP_MJ_WRITE => 2,
            wdk_sys::IRP_MJ_SET_INFORMATION => 4, // Delete or rename
            _ => 0,
        };

        if (rule.operation_mask & op_flag) != 0 {
            // Check process filtering first
            if rule.process_id != 0 {
                let matches_pid = process_id == rule.process_id;
                let is_exclude = rule.is_exclude_process == 1;
                if (is_exclude && matches_pid) || (!is_exclude && !matches_pid) {
                    continue; // Skip this rule
                }
            }

            // Clamp path_len to MAX_RULE_PATH_LEN to prevent out-of-bounds slicing panic
            let path_len = core::cmp::min(rule.path_len as usize, MAX_RULE_PATH_LEN);
            let rule_path = &rule.path[..path_len];

            let matches = match rule.match_type {
                0 => {
                    // Exact Match (case-insensitive)
                    if path_slice.len() == rule_path.len() {
                        let mut eq = true;
                        for j in 0..rule_path.len() {
                            if to_lower_u16(path_slice[j]) != to_lower_u16(rule_path[j]) {
                                eq = false;
                                break;
                            }
                        }
                        eq
                    } else {
                        false
                    }
                }
                1 => matches_prefix_u16(path_slice, rule_path), // Prefix Match
                2 => matches_suffix_u16(path_slice, rule_path), // Suffix Match
                3 => matches_glob_u16(path_slice, rule_path),   // Glob / Wildcard Match
                _ => false,
            };

            if matches {
                matched_rule = Some(rule);
                break;
            }
        }
    }

    if matched_rule.is_none() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    let _rule = matched_rule.unwrap();

    // Generate unique transaction ID for active interception
    static NEXT_TX_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    let transaction_id = NEXT_TX_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Push the event record into user-space mapped Ring Buffer
    let op_code = match major_function {
        wdk_sys::IRP_MJ_CREATE => 1,
        wdk_sys::IRP_MJ_WRITE => 2,
        wdk_sys::IRP_MJ_SET_INFORMATION => 3,
        _ => 0,
    };

    let push_result = file_module.push_event(transaction_id, process_id, op_code, path_slice);

    let start_tail = match push_result {
        Ok(offset) => offset,
        Err(_) => {
            log!("minifilter_pre_op: Failed to push event to ring buffer. Allowing.");
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    };

    // Setup synchronous wait transaction
    let mut tx = PendingTransaction {
        transaction_id,
        event: unsafe { core::mem::zeroed::<wdk_sys::KEVENT>() },
        start_tail,
    };

    // Initialize KEVENT directly in-place so its internal self-referential pointers (WaitListHead)
    // are correctly set to tx.event's actual address on the stack.
    unsafe {
        wdk_sys::ntddk::KeInitializeEvent(
            core::ptr::addr_of_mut!(tx.event),
            wdk_sys::_EVENT_TYPE::NotificationEvent,
            0,
        );
    }

    let tx_ptr = &mut tx as *mut PendingTransaction;
    let tracker_ptr = &raw mut TRANSACTION_TRACKER;
    if let Some(tracker) = unsafe { &mut *tracker_ptr } {
        unsafe {
            tracker.add(tx_ptr);
        }
    }

    // Configure wait timeout (ms -> 100ns relative units)
    let timeout_ms = file_module.config.timeout_ms;
    let timeout_ticks = -(timeout_ms as i64) * 10000;
    let mut timeout_large = wdk_sys::LARGE_INTEGER {
        QuadPart: timeout_ticks,
    };

    // Sleep calling thread (0% CPU cost)
    let wait_status = unsafe {
        wdk_sys::ntddk::KeWaitForSingleObject(
            &mut tx.event as *mut wdk_sys::KEVENT as *mut _,
            wdk_sys::_KWAIT_REASON::UserRequest as i32,
            wdk_sys::_MODE::KernelMode as i8,
            0,
            &mut timeout_large,
        )
    };

    let tracker_ptr = &raw mut TRANSACTION_TRACKER;
    if let Some(tracker) = unsafe { &mut *tracker_ptr } {
        unsafe {
            tracker.remove(tx_ptr);
        }
    }

    // Read the updated event and decision directly from the ring buffer in-place
    let updated_event: crate::ioctl_internal::FileEvent =
        if let Some(ref rb) = file_module.ring_buffer {
            rb.get_ring_buffer(0)
                .read_from_rb::<crate::ioctl_internal::FileEvent>(
                    tx.start_tail,
                    core::mem::size_of::<crate::ringbuffer::RecordHeader>(),
                )
        } else {
            crate::ioctl_internal::FileEvent {
                transaction_id,
                process_id,
                op_code,
                path_len: 0,
                decision: file_module.config.default_action,
                redirect_path_len: 0,
                redirect_path: [0u16; MAX_RULE_PATH_LEN],
            }
        };

    // Evaluate decision: if timeout occurred, apply default action
    let decision = if wait_status == wdk_sys::STATUS_TIMEOUT {
        log!(
            "minifilter_pre_op: Transaction {} timed out after {}ms. Applying default action: {}",
            transaction_id,
            timeout_ms,
            file_module.config.default_action
        );
        file_module.config.default_action
    } else {
        updated_event.decision // 1 = Allow, 2 = Deny, 3 = Redirect
    };

    if decision == 2 {
        log!(
            "minifilter_pre_op: Blocked file operation for process ID {}",
            process_id
        );
        unsafe {
            (*data).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_ACCESS_DENIED;
            (*data).IoStatus.Information = 0;
        }
        return FLT_PREOP_COMPLETE;
    } else if decision == 3 {
        // Process redirection!
        if major_function == wdk_sys::IRP_MJ_CREATE as u32 {
            let pool_tag = u32::from_be_bytes(*b"FvRd");
            let redirect_path_len =
                core::cmp::min(updated_event.redirect_path_len as usize, MAX_RULE_PATH_LEN);
            let buffer_size_bytes = (redirect_path_len * 2) as u64;
            let new_buffer = unsafe {
                wdk_sys::ntddk::ExAllocatePool2(
                    wdk_sys::POOL_FLAG_PAGED,
                    buffer_size_bytes,
                    pool_tag,
                )
            };

            if new_buffer.is_null() {
                log!("minifilter_pre_op: Failed to allocate buffer for redirection path");
                unsafe {
                    (*data).IoStatus.__bindgen_anon_1.Status =
                        wdk_sys::STATUS_INSUFFICIENT_RESOURCES;
                    (*data).IoStatus.Information = 0;
                }
                return FLT_PREOP_COMPLETE;
            }

            // Copy redirection path to the new buffer
            unsafe {
                core::ptr::copy_nonoverlapping(
                    updated_event.redirect_path.as_ptr(),
                    new_buffer as *mut u16,
                    redirect_path_len,
                );
            }

            let file_object = unsafe { (*(*data).Iopb).TargetFileObject };
            if !file_object.is_null() {
                let old_buffer = unsafe { (*file_object).FileName.Buffer };
                if !old_buffer.is_null() {
                    unsafe {
                        wdk_sys::ntddk::ExFreePool(old_buffer as *mut core::ffi::c_void);
                    }
                }

                unsafe {
                    (*file_object).FileName.Buffer = new_buffer as *mut u16;
                    (*file_object).FileName.Length = (redirect_path_len * 2) as u16;
                    (*file_object).FileName.MaximumLength = (redirect_path_len * 2) as u16;
                }

                // Mark callback data dirty to notify Filter Manager
                unsafe {
                    FltSetCallbackDataDirty(data);
                }

                // Return STATUS_REPARSE so Filter Manager reparses the new path
                unsafe {
                    (*data).IoStatus.__bindgen_anon_1.Status = 0x00000104; // STATUS_REPARSE
                    (*data).IoStatus.Information = 1; // IO_REPARSE
                }

                log!(
                    "minifilter_pre_op: Successfully redirected file operation (tx {}) to new path of length {}",
                    transaction_id,
                    redirect_path_len
                );

                return FLT_PREOP_COMPLETE;
            }
        } else {
            log!(
                "minifilter_pre_op: Redirect requested for non-Create operation (mj {}). Disallowing.",
                major_function
            );
            unsafe {
                (*data).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_INVALID_PARAMETER;
                (*data).IoStatus.Information = 0;
            }
            return FLT_PREOP_COMPLETE;
        }
    }

    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Global Minifilter Unload callback.
pub unsafe extern "C" fn minifilter_unload(_flags: FLT_FILTER_UNLOAD_FLAGS) -> NTSTATUS {
    log!("minifilter_unload: Minifilter tearing down");
    wdk_sys::STATUS_SUCCESS
}

// Statically define registered file operations
pub static mut FILE_OPERATIONS: [FLT_OPERATION_REGISTRATION; 4] = [
    FLT_OPERATION_REGISTRATION {
        MajorFunction: wdk_sys::IRP_MJ_CREATE as u8,
        Flags: 0,
        PreOperation: Some(minifilter_pre_op),
        PostOperation: None,
        Reserved1: null_mut(),
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: wdk_sys::IRP_MJ_WRITE as u8,
        Flags: 0,
        PreOperation: Some(minifilter_pre_op),
        PostOperation: None,
        Reserved1: null_mut(),
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: wdk_sys::IRP_MJ_SET_INFORMATION as u8,
        Flags: 0,
        PreOperation: Some(minifilter_pre_op),
        PostOperation: None,
        Reserved1: null_mut(),
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: 0x80, // FLT_AND_INDEX_OF_MAX / IRP_MJ_OPERATION_END marker
        Flags: 0,
        PreOperation: None,
        PostOperation: None,
        Reserved1: null_mut(),
    },
];

/// Statically defines registration details for Filter Manager.
pub unsafe fn get_minifilter_registration() -> FLT_REGISTRATION {
    FLT_REGISTRATION {
        Size: size_of::<FLT_REGISTRATION>() as u16,
        Version: 0x0200, // FLT_REGISTRATION_VERSION
        Flags: 0,
        ContextRegistration: null_mut(),
        OperationRegistration: &raw const FILE_OPERATIONS as *const FLT_OPERATION_REGISTRATION,
        FilterUnloadCallback: Some(minifilter_unload),
        InstanceSetupCallback: None,
        InstanceQueryTeardownCallback: None,
        InstanceTeardownStartCallback: None,
        InstanceTeardownCompleteCallback: None,
        GenerateFileNameCallback: None,
        NormalizeNameComponentCallback: None,
        NormalizeContextCleanupCallback: None,
        TransactionNotificationCallback: None,
        NormalizeNameComponentExCallback: None,
        SectionNotificationCallback: None,
    }
}

/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::context::Context;
use crate::ioctl_user::{DivertAddress, DivertData, DivertDataFlow};
use crate::log;
use crate::ringbuffer::{RecordHeader, RecordType};
use crate::wdk_ext::ndis::*;
use core::ptr::null_mut;
use wdk_sys::{GUID, STATUS_SUCCESS, NTSTATUS};

struct ParsedIncomingValues {
    ipv4: bool,
    inbound: bool,
    layer_id: u16,
}

#[inline(always)]
unsafe fn process_flow_data(
    context_ptr: &mut Context,
    parsed_values: &ParsedIncomingValues,
    cpu_index: u32,
) {
    // Placeholder: Process ALE flow data
}

pub unsafe extern "C" fn classify_flow(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut core::ffi::c_void,
    filter: *const FWPS_FILTER0,
    flow_context: UINT64,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    if !have_write_right(classify_out) {
        return;
    }

    let parsed_incoming_values = match parse_incoming_values_flow(in_fixed_values) {
        Some(value) => value,
        None => {
            log!("got invalid layer in flow classifyFn, should not happen");
            return;
        }
    };

    let classify_out = unsafe { &mut *classify_out };

    let raw_ctx = unsafe { (*filter).context };
    if raw_ctx == 0 {
        return;
    }
    let context_ptr = raw_ctx as *mut Context;

    let cpu_index = unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(null_mut()) };

    unsafe {
        process_flow_data(
            &mut *context_ptr,
            &parsed_incoming_values,
            cpu_index,
        );
    }

    unsafe {
        ((*context_ptr).network_ctx).metrics_inc_received();
        // Note: For ALE layers, typically we PERMIT or BLOCK instead of CONTINUE.
        classify_out.actionType = FWP_ACTION_PERMIT;
    }
}

fn have_write_right(classify_out: *const FWPS_CLASSIFY_OUT0) -> bool {
    unsafe { ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 }
}

fn parse_incoming_values_flow(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
) -> Option<ParsedIncomingValues> {
    // Placeholder for ALE Flow specific values
    Some(ParsedIncomingValues {
        ipv4: true,
        inbound: true,
        layer_id: unsafe { (*in_fixed_values).layerId },
    })
}

pub unsafe extern "C" fn notify_flow(
    notify_type: FWPS_CALLOUT_NOTIFY_TYPE,
    filter_key: *const GUID,
    filter: *mut FWPS_FILTER0,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub unsafe extern "C" fn flow_delete_flow(_layer_id: u16, _callout_id: u32, _flow_context: u64) {
    // Flow cleanup if needed
}
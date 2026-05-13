/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::context::Context;
use crate::ioctl_user::{DivertAddress, DivertData, DivertDataNetwork};
use crate::log;
use crate::ringbuffer::{RecordHeader, RecordType};
use crate::wdk_ext::ndis::*;
use core::ptr::null_mut;
use core::slice;
use wdk_sys::{GUID, PMDL, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};

struct ParsedIncomingValues {
    ipv4: bool,
    inbound: bool,
    layer_id: u16,
    ifindex: u32,
    sub_ifindex: u32,
}

#[inline(always)]
unsafe fn is_self_injected_packet(
    context_ptr: *const Context,
    nbl: *const NET_BUFFER_LIST,
    parsed_values: &ParsedIncomingValues,
) -> bool {
    // Stream layer usually doesn't have an NBL in the same way, or the injection mechanism is different.
    // Placeholder logic.
    false
}

#[inline(always)]
unsafe fn filter_packet(
    _context_ptr: *const Context,
    _parsed_values: &ParsedIncomingValues,
) -> bool {
    true
}

#[inline(always)]
unsafe fn process_stream_data(
    context_ptr: &mut Context,
    stream_data: *const FWPS_STREAM_CALLOUT_IO_PACKET0,
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
    parsed_values: &ParsedIncomingValues,
    cpu_index: u32,
) {
    // Placeholder: Process stream data
}

pub unsafe extern "C" fn classify_stream(
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

    let parsed_incoming_values = match parse_incoming_values_stream(in_fixed_values) {
        Some(value) => value,
        None => {
            log!("got invalid layer in stream classifyFn, should not happen");
            return;
        }
    };

    let classify_out = unsafe { &mut *classify_out };
    // Layer data for stream is typically FWPS_STREAM_CALLOUT_IO_PACKET0
    let stream_packet = layer_data as *mut FWPS_STREAM_CALLOUT_IO_PACKET0;

    if stream_packet.is_null() {
        classify_out.actionType = FWP_ACTION_CONTINUE;
        return;
    }

    let raw_ctx = unsafe { (*filter).context };
    if raw_ctx == 0 {
        return;
    }
    let context_ptr = raw_ctx as *mut Context;

    // Placeholder: Self-injection check for stream data
    // if unsafe { is_self_injected_stream(...) } { ... }

    let cpu_index = unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(null_mut()) };

    unsafe {
        process_stream_data(
            &mut *context_ptr,
            stream_packet,
            in_meta_values,
            &parsed_incoming_values,
            cpu_index,
        );
    }

    unsafe {
        if (*context_ptr).network_ctx.packet_read_only {
            ((*context_ptr).network_ctx).metrics_inc_received();
            classify_out.actionType = FWP_ACTION_CONTINUE;
        } else {
            ((*context_ptr).network_ctx).metrics_inc_received();
            classify_out.flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            // Note: For stream layer, actionType might need to be FWP_ACTION_BLOCK
            // or FWP_ACTION_PERMIT depending on whether data is absorbed completely.
            classify_out.actionType = FWP_ACTION_BLOCK;
        }
    }
}

fn have_write_right(classify_out: *const FWPS_CLASSIFY_OUT0) -> bool {
    unsafe { ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 }
}

fn parse_incoming_values_stream(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
) -> Option<ParsedIncomingValues> {
    // Placeholder
    Some(ParsedIncomingValues {
        ipv4: true,
        inbound: true,
        layer_id: unsafe { (*in_fixed_values).layerId },
        ifindex: 0,
        sub_ifindex: 0,
    })
}

pub unsafe extern "C" fn notify_stream(
    notify_type: FWPS_CALLOUT_NOTIFY_TYPE,
    filter_key: *const GUID,
    filter: *mut FWPS_FILTER0,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub unsafe extern "C" fn flow_delete_stream(_layer_id: u16, _callout_id: u32, _flow_context: u64) {
    // Flow cleanup if needed
}
/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::context::Context;
use crate::ioctl_user::{DivertAddress, DivertData, DivertDataSocket, Event, LAYER_SOCKET};
use crate::log;
use crate::ringbuffer::RecordHeader;
use crate::wdk_ext::ndis::*;
use crate::network::bpf::{bpf_run_filter, BpfContext};
use core::ptr::null_mut;
use wdk_sys::{GUID, STATUS_SUCCESS, NTSTATUS};

struct ParsedIncomingValues {
    ipv4: bool,
    inbound: bool, // This is outbound for connect
    layer_id: u16,
    process_id: u32,
    remote_addr: [u8; 16],
    remote_port: u16,
    local_addr: [u8; 16],
    local_port: u16,
    protocol: u8,
}

#[inline(always)]
unsafe fn filter_socket(
    context_ptr: *const Context,
    _parsed_values: &ParsedIncomingValues,
) -> bool {
    let ctx = unsafe { &*context_ptr };
    let net_mod_ptr = ctx.get_network_module_ptr();
    if net_mod_ptr.is_null() {
        return false;
    }
    let bpf_program = unsafe { &(*net_mod_ptr).bpf_program };
    if bpf_program.is_empty() {
        return true; // Match everything if no filter loaded
    }

    let mut addr = DivertAddress {
        timestamp: 0,
        flags: 0,
        reserved2: 0,
        data: DivertData {
            socket: DivertDataSocket {
                endpoint_id: 0,
                process_id: _parsed_values.process_id,
                filter_id: 0,
                layer: LAYER_SOCKET as u8,
                flags: 0,
                reserved: [0; 6],
            },
        },
    };
    addr.set_layer(LAYER_SOCKET as u8);
    addr.set_ipv6(!_parsed_values.ipv4);
    addr.set_outbound(!_parsed_values.inbound);

    let bpf_ctx = BpfContext {
        packet: &[],
        address: &addr,
    };

    bpf_run_filter(bpf_program, &bpf_ctx) != 0
}

#[inline(always)]
unsafe fn process_socket_data(
    context_ptr: &mut Context,
    parsed_values: &ParsedIncomingValues,
    blocked: bool,
    _cpu_index: u32,
) {
    let net_ctx = context_ptr.get_network_ctx_ptr();
    if net_ctx.is_null() {
        return;
    }
    let net_ctx_ref = unsafe { &mut *net_ctx };

    if let Some(ref rb) = net_ctx_ref.ale_ring_buffer {
        let mut addr = DivertAddress {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            data: DivertData {
                socket: DivertDataSocket {
                    endpoint_id: 0, // Not available at this layer
                    process_id: parsed_values.process_id,
                    filter_id: 0, // Placeholder
                    layer: LAYER_SOCKET as u8,
                    flags: if blocked { 1 } else { 0 },
                    reserved: [0; 6],
                },
            },
        };
        addr.set_layer(LAYER_SOCKET as u8);
        addr.set_ipv6(!parsed_values.ipv4);
        addr.set_outbound(true); // AUTH_CONNECT is always outbound
        addr.set_event(Event::SocketConnect as u8);

        let addr_header = RecordHeader {
            len: core::mem::size_of::<DivertAddress>() as u32,
            _reserved: 0,
        };

        let address_bytes = unsafe {
            core::slice::from_raw_parts(
                &addr as *const DivertAddress as *const u8,
                core::mem::size_of::<DivertAddress>(),
            )
        };

        let res = rb.push_record(&addr_header, address_bytes);

        match res {
            Ok(_) => {
                net_ctx_ref.metrics_inc_received();
            }
            Err(status) => {
                log!("rb push failed for socket data: {:#x}", status);
                net_ctx_ref.metrics_inc_dropped();
            }
        }
    }
}

pub unsafe extern "C" fn classify_socket(
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

    let parsed_incoming_values = match parse_incoming_values_socket(in_fixed_values, in_meta_values) {
        Some(value) => value,
        None => {
            log!("got invalid layer in socket classifyFn, should not happen");
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

    let net_ctx = unsafe { (*context_ptr).get_network_ctx_ptr() };
    if net_ctx.is_null() {
        return;
    }
    let net_ctx_ref = unsafe { &mut *net_ctx };

    let pass_filter = unsafe { filter_socket(context_ptr, &parsed_incoming_values) };
    let blocked = !net_ctx_ref.packet_read_only && pass_filter;

    unsafe {
        process_socket_data(
            &mut *context_ptr,
            &parsed_incoming_values,
            blocked,
            cpu_index,
        );
    }

    if blocked {
        classify_out.actionType = FWP_ACTION_BLOCK;
        classify_out.rights &= !FWPS_RIGHT_ACTION_WRITE;
        unsafe {
            (*net_ctx).metrics_inc_dropped();
        }
    } else {
        classify_out.actionType = FWP_ACTION_PERMIT;
    }
}

fn have_write_right(classify_out: *const FWPS_CLASSIFY_OUT0) -> bool {
    unsafe { ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 }
}

fn parse_incoming_values_socket(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
) -> Option<ParsedIncomingValues> {
    let layer_id = unsafe { (*in_fixed_values).layerId };
    let ipv4 = match layer_id as i32 {
        FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_AUTH_CONNECT_V4 => true,
        FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_AUTH_CONNECT_V6 => false,
        _ => return None,
    };

    let values = unsafe {
        core::slice::from_raw_parts(
            (*in_fixed_values).incomingValue,
            (*in_fixed_values).valueCount as usize,
        )
    };

    let process_id = if !in_meta_values.is_null() {
        let meta = unsafe { &*in_meta_values };
        if (meta.currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0 {
            meta.processId as u32
        } else {
            0
        }
    } else {
        0
    };

    let (
        mut local_addr,
        local_port,
        mut remote_addr,
        remote_port,
        protocol,
    ) = if ipv4 {
        let local_addr_v4 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V4__FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .uint32
        };
        let local_port_v4 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V4__FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let remote_addr_v4 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V4__FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .uint32
        };
        let remote_port_v4 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V4__FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let protocol_v4 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V4__FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL as usize]
                .value
                .__bindgen_anon_1
                .uint8
        };
        let mut local = [0u8; 16];
        local[..4].copy_from_slice(&local_addr_v4.to_be_bytes());
        let mut remote = [0u8; 16];
        remote[..4].copy_from_slice(&remote_addr_v4.to_be_bytes());

        (local, local_port_v4, remote, remote_port_v4, protocol_v4)
    } else {
        let local_addr_v6 = unsafe {
            &*values[FWPS_FIELDS_ALE_AUTH_CONNECT_V6__FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .byteArray16
        };
        let local_port_v6 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V6__FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let remote_addr_v6 = unsafe {
            &*values[FWPS_FIELDS_ALE_AUTH_CONNECT_V6__FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .byteArray16
        };
        let remote_port_v6 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V6__FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let protocol_v6 = unsafe {
            values[FWPS_FIELDS_ALE_AUTH_CONNECT_V6__FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL as usize]
                .value
                .__bindgen_anon_1
                .uint8
        };
        (local_addr_v6.byteArray16, local_port_v6, remote_addr_v6.byteArray16, remote_port_v6, protocol_v6)
    };

    Some(ParsedIncomingValues {
        ipv4,
        inbound: false, // AUTH_CONNECT is outbound
        layer_id,
        process_id,
        remote_addr,
        remote_port,
        local_addr,
        local_port,
        protocol,
    })
}


pub unsafe extern "C" fn notify_socket(
    notify_type: FWPS_CALLOUT_NOTIFY_TYPE,
    filter_key: *const GUID,
    filter: *mut FWPS_FILTER0,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub unsafe extern "C" fn flow_delete_socket(_layer_id: u16, _callout_id: u32, _flow_context: u64) {
    // Flow cleanup if needed
}
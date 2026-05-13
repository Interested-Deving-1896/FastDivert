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
    unsafe {
        let injection_handle = if parsed_values.inbound {
            if parsed_values.ipv4 {
                (*context_ptr).network_ctx.inject_handle_in_v4
            } else {
                (*context_ptr).network_ctx.inject_handle_in_v6
            }
        } else {
            if parsed_values.ipv4 {
                (*context_ptr).network_ctx.inject_handle_out_v4
            } else {
                (*context_ptr).network_ctx.inject_handle_out_v6
            }
        };

        if !injection_handle.is_null() {
            let injection_state = FwpsQueryPacketInjectionState0(injection_handle, nbl, null_mut());

            const INJECTED_BY_SELF: i32 = 1;
            const PREVIOUSLY_INJECTED_BY_SELF: i32 = 3;

            let state_val = injection_state as i32;
            if state_val == INJECTED_BY_SELF || state_val == PREVIOUSLY_INJECTED_BY_SELF {
                return true;
            }
        }
        false
    }
}

#[inline(always)]
unsafe fn filter_packet(
    _context_ptr: *const Context,
    _nb: PNET_BUFFER,
    _parsed_values: &ParsedIncomingValues,
) -> bool {
    true
}

#[inline(always)]
unsafe fn process_net_buffer_list(
    context_ptr: &mut Context,
    nbl: *mut NET_BUFFER_LIST,
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
    parsed_values: &ParsedIncomingValues,
    cpu_index: u32,
) {
    unsafe {
        let mut ip_header_size: u32 = 0;
        if parsed_values.inbound && !in_meta_values.is_null() {
            let meta = &*in_meta_values;
            if (meta.currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) != 0 {
                ip_header_size = meta.ipHeaderSize;
            }
        }

        let mut current_nbl = nbl;
        while !current_nbl.is_null() {
            let mut current_nb = NET_BUFFER_LIST_FIRST_NB(current_nbl);
            while !current_nb.is_null() {
                if !filter_packet(context_ptr, current_nb, parsed_values) {
                    current_nb = NET_BUFFER_NEXT_NB(current_nb);
                    continue;
                }

                let mut retreated = false;
                if ip_header_size > 0 {
                    if NdisRetreatNetBufferDataStart(current_nb, ip_header_size, 0, None) == 0 {
                        retreated = true;
                    }
                }

                let data_length = NET_BUFFER_DATA_LENGTH(current_nb);
                let current_mdl = NET_BUFFER_CURRENT_MDL(current_nb) as PMDL;
                let current_offset = NET_BUFFER_CURRENT_MDL_OFFSET(current_nb) as usize;

                let packet_header = RecordHeader {
                    len: data_length,
                    ty: RecordType::PacketData as u32,
                };

                let rb = (*context_ptr).network_ctx.ring_buffer;
                if !rb.is_null() {
                    let mut addr = DivertAddress {
                        timestamp: 0,
                        flags: 0,
                        reserved2: 0,
                        data: DivertData {
                            network: DivertDataNetwork {
                                if_idx: parsed_values.ifindex,
                                sub_if_idx: parsed_values.sub_ifindex,
                            },
                        },
                    };
                    addr.set_ipv6(!parsed_values.ipv4);
                    addr.set_outbound(!parsed_values.inbound);

                    let addr_header = RecordHeader {
                        len: core::mem::size_of::<DivertAddress>() as u32,
                        ty: RecordType::Address as u32,
                    };

                    let address_bytes = core::slice::from_raw_parts(
                        &addr as *const DivertAddress as *const u8,
                        core::mem::size_of::<DivertAddress>(),
                    );

                    let expected_total_size = core::mem::size_of::<RecordHeader>()
                        + address_bytes.len()
                        + core::mem::size_of::<RecordHeader>()
                        + data_length as usize;

                    let res = (*rb).transaction(cpu_index, expected_total_size, |tx| {
                        tx.push_slice(&addr_header, address_bytes)?;
                        tx.push_mdl(
                            &packet_header,
                            current_mdl,
                            current_offset,
                            data_length as usize,
                        )?;
                        Ok(())
                    });
                    match res {
                        Ok(_) => {}
                        Err(status) => match status {
                            STATUS_INSUFFICIENT_RESOURCES => {
                                context_ptr.network_ctx.metrics_inc_dropped();
                            }
                            _ => {
                                log!("rb push failed: {:#x}", status);
                            }
                        },
                    }
                }

                if retreated {
                    NdisAdvanceNetBufferDataStart(current_nb, ip_header_size, 0, None);
                }

                current_nb = NET_BUFFER_NEXT_NB(current_nb);
            }

            current_nbl = NET_BUFFER_LIST_NEXT_NBL(current_nbl);
        }
    }
}

pub unsafe extern "C" fn classify_transport(
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

    let parsed_incoming_values = match parse_incoming_values_transport(in_fixed_values) {
        Some(value) => value,
        None => {
            log!("got invalid layer in transport classifyFn, should not happen");
            return;
        }
    };

    let classify_out = unsafe { &mut *classify_out };
    let nbl = layer_data as *mut NET_BUFFER_LIST;

    if nbl.is_null() {
        classify_out.actionType = FWP_ACTION_CONTINUE;
        return;
    }

    let raw_ctx = unsafe { (*filter).context };
    if raw_ctx == 0 {
        return;
    }
    let context_ptr = raw_ctx as *mut Context;

    if unsafe { is_self_injected_packet(context_ptr, nbl, &parsed_incoming_values) } {
        classify_out.actionType = FWP_ACTION_CONTINUE;
        return;
    }

    let cpu_index = unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(null_mut()) };

    unsafe {
        process_net_buffer_list(
            &mut *context_ptr,
            nbl,
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
            classify_out.actionType = FWP_ACTION_BLOCK;
        }
    }
}

fn have_write_right(classify_out: *const FWPS_CLASSIFY_OUT0) -> bool {
    unsafe { ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 }
}

fn parse_incoming_values_transport(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
) -> Option<ParsedIncomingValues> {
    // Placeholder: Actual implementation will need to parse transport layer specific values
    // This is highly dependent on the specific FWPM_LAYER_* being used.
    // For now, we'll just return a dummy structure.
    Some(ParsedIncomingValues {
        ipv4: true,
        inbound: true,
        layer_id: unsafe { (*in_fixed_values).layerId },
        ifindex: 0,
        sub_ifindex: 0,
    })
}

pub unsafe extern "C" fn notify_transport(
    notify_type: FWPS_CALLOUT_NOTIFY_TYPE,
    filter_key: *const GUID,
    filter: *mut FWPS_FILTER0,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub unsafe extern "C" fn flow_delete_transport(_layer_id: u16, _callout_id: u32, _flow_context: u64) {
    // Flow cleanup if needed
}
use crate::context::Context;
use crate::ioctl_user::{DivertAddress, DivertData, DivertDataFlow, Event, LAYER_FLOW};
use crate::log;
use crate::ringbuffer::RecordHeader;
use crate::wdk_ext::ndis::*;
use core::ptr::null_mut;
use wdk_sys::{GUID, NTSTATUS, STATUS_SUCCESS};

struct ParsedIncomingValues {
    ipv4: bool,
    inbound: bool,
    layer_id: u16,
    process_id: u32,
    remote_addr: [u8; 16],
    remote_port: u16,
    local_addr: [u8; 16],
    local_port: u16,
    protocol: u8,
}

#[inline(always)]
unsafe fn process_flow_data(
    context_ptr: &mut Context,
    parsed_values: &ParsedIncomingValues,
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
                flow: DivertDataFlow {
                    endpoint_id: 0, // Not available at this layer
                    process_id: parsed_values.process_id,
                    filter_id: 0, // Placeholder
                    layer: LAYER_FLOW as u8,
                    flags: 0,
                    reserved: [0; 6],
                },
            },
        };
        addr.set_ipv6(!parsed_values.ipv4);
        addr.set_outbound(!parsed_values.inbound);
        addr.set_event(Event::FlowEstablished as u8);

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
                log!("rb push failed for flow data: {:#x}", status);
                net_ctx_ref.metrics_inc_dropped();
            }
        }
    }
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

    let parsed_incoming_values = match parse_incoming_values_flow(in_fixed_values, in_meta_values) {
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
        process_flow_data(&mut *context_ptr, &parsed_incoming_values, cpu_index);
    }

    // For ALE layers, we must permit the action to allow the flow to be created.
    classify_out.actionType = FWP_ACTION_PERMIT;
}

fn have_write_right(classify_out: *const FWPS_CLASSIFY_OUT0) -> bool {
    unsafe { ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 }
}

fn parse_incoming_values_flow(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
) -> Option<ParsedIncomingValues> {
    let layer_id = unsafe { (*in_fixed_values).layerId };
    let (ipv4, inbound) = match layer_id as i32 {
        FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 => (true, true), // Inbound is not explicit, but we can treat established as such
        FWPS_BUILTIN_LAYERS__FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6 => (false, true),
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

    let (mut local_addr, local_port, mut remote_addr, remote_port, protocol) = if ipv4 {
        let local_addr_v4 = unsafe {
            values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .uint32
        };
        let local_port_v4 = unsafe {
            values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let remote_addr_v4 = unsafe {
            values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .uint32
        };
        let remote_port_v4 = unsafe {
            values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let protocol_v4 = unsafe {
            values
                [FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL
                    as usize]
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
            &*values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .byteArray16
        };
        let local_port_v6 = unsafe {
            values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let remote_addr_v6 = unsafe {
            &*values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS as usize]
                .value
                .__bindgen_anon_1
                .byteArray16
        };
        let remote_port_v6 = unsafe {
            values[FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT as usize]
                .value
                .__bindgen_anon_1
                .uint16
        };
        let protocol_v6 = unsafe {
            values
                [FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6__FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL
                    as usize]
                .value
                .__bindgen_anon_1
                .uint8
        };
        (
            local_addr_v6.byteArray16,
            local_port_v6,
            remote_addr_v6.byteArray16,
            remote_port_v6,
            protocol_v6,
        )
    };

    Some(ParsedIncomingValues {
        ipv4,
        inbound,
        layer_id,
        process_id,
        remote_addr,
        remote_port,
        local_addr,
        local_port,
        protocol,
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

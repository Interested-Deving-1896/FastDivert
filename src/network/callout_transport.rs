use crate::context::Context;
use crate::ioctl_user::{DivertAddress, DivertData, DivertDataNetwork};
use crate::log;
use crate::ringbuffer::RecordHeader;
use crate::wdk_ext::ndis::*;
use crate::network::bpf::{bpf_run_filter, BpfContext};
use core::ptr::null_mut;
use core::slice;
use wdk_sys::{GUID, HANDLE, NTSTATUS, NT_SUCCESS, PMDL, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};

pub struct TransportLayer {
    pub inject_handle_in_v4: HANDLE,
    pub inject_handle_out_v4: HANDLE,
    pub inject_handle_in_v6: HANDLE,
    pub inject_handle_out_v6: HANDLE,
}

impl TransportLayer {
    pub fn initialize() -> Result<Self, NTSTATUS> {
        unsafe {
            let mut inject_handle_in_v4 = null_mut();
            let mut inject_handle_out_v4 = null_mut();
            let mut inject_handle_in_v6 = null_mut();
            let mut inject_handle_out_v6 = null_mut();

            let status = FwpsInjectionHandleCreate0(
                AF_INET as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_TRANSPORT,
                &mut inject_handle_in_v4,
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_TRANSPORT,
                &mut inject_handle_out_v4,
            );
            if !NT_SUCCESS(status) {
                FwpsInjectionHandleDestroy0(inject_handle_in_v4);
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET6 as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_TRANSPORT,
                &mut inject_handle_in_v6,
            );
            if !NT_SUCCESS(status) {
                FwpsInjectionHandleDestroy0(inject_handle_in_v4);
                FwpsInjectionHandleDestroy0(inject_handle_out_v4);
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET6 as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_TRANSPORT,
                &mut inject_handle_out_v6,
            );
            if !NT_SUCCESS(status) {
                FwpsInjectionHandleDestroy0(inject_handle_in_v4);
                FwpsInjectionHandleDestroy0(inject_handle_out_v4);
                FwpsInjectionHandleDestroy0(inject_handle_in_v6);
                return Err(status);
            }

            Ok(Self {
                inject_handle_in_v4,
                inject_handle_out_v4,
                inject_handle_in_v6,
                inject_handle_out_v6,
            })
        }
    }

    pub fn is_self_injected(&self, nbl: *const NET_BUFFER_LIST, inbound: bool, ipv4: bool) -> bool {
        unsafe {
            let injection_handle = if inbound {
                if ipv4 {
                    self.inject_handle_in_v4
                } else {
                    self.inject_handle_in_v6
                }
            } else {
                if ipv4 {
                    self.inject_handle_out_v4
                } else {
                    self.inject_handle_out_v6
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

    pub fn inject(
        &self,
        is_inbound: bool,
        is_ipv6: bool,
        if_idx: u32,
        sub_if_idx: u32,
        nbl: *mut NET_BUFFER_LIST,
        completion_ctx_ptr: *mut core::ffi::c_void,
    ) -> NTSTATUS {
        unsafe {
            if nbl.is_null() {
                return wdk_sys::STATUS_INSUFFICIENT_RESOURCES;
            }

            let address_family = if is_ipv6 {
                AF_INET6 as u16
            } else {
                AF_INET as u16
            };

            let completion_fn: crate::wdk_ext::ndis::FWPS_INJECT_COMPLETE0 = Some(crate::network::inject::injection_completion_fn);

            let status = if is_inbound {
                let injection_handle = if is_ipv6 {
                    self.inject_handle_in_v6
                } else {
                    self.inject_handle_in_v4
                };

                if injection_handle.is_null() {
                    log!("TransportLayer::inject: inbound injection handle is null!");
                    return wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
                }

                FwpsInjectTransportReceiveAsync0(
                    injection_handle,
                    null_mut(), // injectionContext
                    null_mut(), // reserved
                    0,          // flags
                    address_family,
                    1,          // compartmentId (default)
                    if_idx,
                    sub_if_idx,
                    nbl,
                    completion_fn,
                    completion_ctx_ptr,
                )
            } else {
                let injection_handle = if is_ipv6 {
                    self.inject_handle_out_v6
                } else {
                    self.inject_handle_out_v4
                };

                if injection_handle.is_null() {
                    log!("TransportLayer::inject: outbound injection handle is null!");
                    return wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
                }

                FwpsInjectTransportSendAsync0(
                    injection_handle,
                    null_mut(), // injectionContext
                    0,          // endpointHandle (optional, 0 is fine)
                    0,          // flags
                    null_mut(), // sendArgs (optional)
                    address_family,
                    1,          // compartmentId (default)
                    nbl,
                    completion_fn,
                    completion_ctx_ptr,
                )
            };

            if !wdk::nt_success(status) {
                if let Some(comp_fn) = completion_fn {
                    comp_fn(completion_ctx_ptr, nbl, 0);
                }
                log!("FwpsInjectTransport failed: {:#010X}", status);
            }

            status
        }
    }
}

impl Drop for TransportLayer {
    fn drop(&mut self) {
        unsafe {
            if !self.inject_handle_in_v4.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_in_v4);
            }
            if !self.inject_handle_out_v4.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_out_v4);
            }
            if !self.inject_handle_in_v6.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_in_v6);
            }
            if !self.inject_handle_out_v6.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_out_v6);
            }
        }
    }
}

struct ParsedIncomingValues {
    ipv4: bool,
    inbound: bool,
    layer_id: u16,
    ifindex: u32,
    sub_ifindex: u32,
}

#[inline(always)]
unsafe fn filter_packet(
    context_ptr: *const Context,
    nb: PNET_BUFFER,
    _parsed_values: &ParsedIncomingValues,
) -> bool {
    let ctx = unsafe { &*context_ptr };
    let net_mod_ptr = ctx.get_network_module_ptr();
    if net_mod_ptr.is_null() {
        return false;
    }
    let bpf_program = unsafe { &(*net_mod_ptr).bpf_program };
    if bpf_program.is_empty() {
        return true;
    }

    // For BPF filtering, we need access to the packet payload.
    // If the packet is fragmented across multiple MDLs, we might only check the first few bytes.
    let current_mdl = unsafe { NET_BUFFER_CURRENT_MDL(nb) as PMDL };
    if current_mdl.is_null() {
        return false;
    }

    let offset = unsafe { NET_BUFFER_CURRENT_MDL_OFFSET(nb) as usize };
    let length = unsafe { NET_BUFFER_DATA_LENGTH(nb) as usize };
    let mdl_byte_count = unsafe { (*current_mdl).ByteCount as usize };

    // Check if the required data is in the first MDL. We only check up to what's available.
    let available_in_first_mdl = if mdl_byte_count > offset {
        mdl_byte_count - offset
    } else {
        0
    };

    let check_len = core::cmp::min(length, available_in_first_mdl);

    let src_addr = crate::wdk_ext::ntddk::MmGetSystemAddressForMdlSafe(
        current_mdl,
        wdk_sys::_MM_PAGE_PRIORITY::HighPagePriority as u32,
    );

    if src_addr.is_null() {
        return false;
    }

    let packet_slice = unsafe { core::slice::from_raw_parts((src_addr as *const u8).add(offset), check_len) };

    let mut addr = crate::ioctl_user::DivertAddress {
        timestamp: 0,
        flags: 0,
        reserved2: 0,
        data: crate::ioctl_user::DivertData {
            network: crate::ioctl_user::DivertDataNetwork {
                if_idx: _parsed_values.ifindex,
                sub_if_idx: _parsed_values.sub_ifindex,
            },
        },
    };
    addr.set_ipv6(!_parsed_values.ipv4);
    addr.set_outbound(!_parsed_values.inbound);

    let bpf_ctx = BpfContext {
        packet: packet_slice,
        address: &addr,
    };

    bpf_run_filter(bpf_program, &bpf_ctx) != 0
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
                let mut retreated = false;
                if ip_header_size > 0 {
                    if NdisRetreatNetBufferDataStart(current_nb, ip_header_size, 0, None) == 0 {
                        retreated = true;
                    }
                }

                if !filter_packet(context_ptr, current_nb, parsed_values) {
                    if retreated {
                        NdisAdvanceNetBufferDataStart(current_nb, ip_header_size, 0, None);
                    }
                    current_nb = NET_BUFFER_NEXT_NB(current_nb);
                    continue;
                }

                let data_length = NET_BUFFER_DATA_LENGTH(current_nb);
                let current_mdl = NET_BUFFER_CURRENT_MDL(current_nb) as PMDL;
                let current_offset = NET_BUFFER_CURRENT_MDL_OFFSET(current_nb) as usize;

                let net_ctx = (*context_ptr).get_network_ctx_ptr();
                if !net_ctx.is_null() {
                    let net_ctx_ref = &mut *net_ctx;
                    if let Some(ref rb) = net_ctx_ref.ring_buffer {
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

                        let packet_header = RecordHeader {
                            len: (core::mem::size_of::<DivertAddress>() + data_length as usize) as u32,
                            _reserved: 0,
                        };

                        let address_bytes = core::slice::from_raw_parts(
                            &addr as *const DivertAddress as *const u8,
                            core::mem::size_of::<DivertAddress>(),
                        );

                        let expected_total_size = core::mem::size_of::<RecordHeader>()
                            + address_bytes.len()
                            + data_length as usize;

                        let res = rb.transaction(cpu_index, expected_total_size, |tx| {
                            tx.push_slice(&packet_header, address_bytes)?;
                            tx.push_mdl_only(
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
                                    net_ctx_ref.metrics_inc_dropped();
                                }
                                _ => {
                                    log!("rb push failed: {:#x}", status);
                                }
                            },
                        }
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
    _flow_context: UINT64,
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

    let net_ctx = unsafe { (*context_ptr).get_network_ctx_ptr() };
    if net_ctx.is_null() {
        return;
    }

    let is_self = unsafe {
        match &(*net_ctx).active_layer {
            crate::network::context::WfpLayer::Transport(layer) => {
                layer.is_self_injected(nbl, parsed_incoming_values.inbound, parsed_incoming_values.ipv4)
            }
            _ => false,
        }
    };

    if is_self {
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
        let net_ctx_ref = &mut *net_ctx;
        net_ctx_ref.metrics_inc_received();
        if net_ctx_ref.packet_read_only {
            classify_out.actionType = FWP_ACTION_CONTINUE;
        } else {
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
    if in_fixed_values.is_null() {
        return None;
    }

    let ipv4: bool;
    let inbound: bool;
    let layer_id = unsafe { (*in_fixed_values).layerId };
    let flags: u32;
    let ifindex: u32;
    let sub_ifindex: u32;

    unsafe {
        let index_get_flags: usize;
        let index_get_ifindex: usize;
        let index_get_sub_ifindex: usize;

        match (layer_id as i32) {
            FWPS_BUILTIN_LAYERS__FWPS_LAYER_INBOUND_TRANSPORT_V4 => {
                inbound = true;
                ipv4 = true;
                index_get_flags =
                    FWPS_FIELDS_INBOUND_TRANSPORT_V4__FWPS_FIELD_INBOUND_TRANSPORT_V4_FLAGS as usize;
                index_get_ifindex =
                    FWPS_FIELDS_INBOUND_TRANSPORT_V4__FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_INDEX
                        as usize;
                index_get_sub_ifindex = FWPS_FIELDS_INBOUND_TRANSPORT_V4__FWPS_FIELD_INBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX
                    as usize;
            }
            FWPS_BUILTIN_LAYERS__FWPS_LAYER_OUTBOUND_TRANSPORT_V4 => {
                inbound = false;
                ipv4 = true;
                index_get_flags =
                    FWPS_FIELDS_OUTBOUND_TRANSPORT_V4__FWPS_FIELD_OUTBOUND_TRANSPORT_V4_FLAGS
                        as usize;
                index_get_ifindex = FWPS_FIELDS_OUTBOUND_TRANSPORT_V4__FWPS_FIELD_OUTBOUND_TRANSPORT_V4_INTERFACE_INDEX
                    as usize;
                index_get_sub_ifindex = FWPS_FIELDS_OUTBOUND_TRANSPORT_V4__FWPS_FIELD_OUTBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX
                    as usize;
            }
            FWPS_BUILTIN_LAYERS__FWPS_LAYER_INBOUND_TRANSPORT_V6 => {
                inbound = true;
                ipv4 = false;
                index_get_flags =
                    FWPS_FIELDS_INBOUND_TRANSPORT_V6__FWPS_FIELD_INBOUND_TRANSPORT_V6_FLAGS as usize;
                index_get_ifindex =
                    FWPS_FIELDS_INBOUND_TRANSPORT_V6__FWPS_FIELD_INBOUND_TRANSPORT_V6_INTERFACE_INDEX
                        as usize;
                index_get_sub_ifindex = FWPS_FIELDS_INBOUND_TRANSPORT_V6__FWPS_FIELD_INBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX
                    as usize;
            }
            FWPS_BUILTIN_LAYERS__FWPS_LAYER_OUTBOUND_TRANSPORT_V6 => {
                inbound = false;
                ipv4 = false;
                index_get_flags =
                    FWPS_FIELDS_OUTBOUND_TRANSPORT_V6__FWPS_FIELD_OUTBOUND_TRANSPORT_V6_FLAGS
                        as usize;
                index_get_ifindex = FWPS_FIELDS_OUTBOUND_TRANSPORT_V6__FWPS_FIELD_OUTBOUND_TRANSPORT_V6_INTERFACE_INDEX
                    as usize;
                index_get_sub_ifindex = FWPS_FIELDS_OUTBOUND_TRANSPORT_V6__FWPS_FIELD_OUTBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX
                    as usize;
            }
            _ => {
                log!("parse_incoming_values_transport: unknown layer_id = {}, valueCount = {}", layer_id, (*in_fixed_values).valueCount);
                return None;
            }
        }

        let incoming_value = slice::from_raw_parts(
            (*in_fixed_values).incomingValue,
            (*in_fixed_values).valueCount as usize,
        );

        flags = if index_get_flags < incoming_value.len() {
            incoming_value[index_get_flags]
                .value
                .__bindgen_anon_1
                .uint32
        } else {
            0
        };

        ifindex = if index_get_ifindex < incoming_value.len() {
            incoming_value[index_get_ifindex]
                .value
                .__bindgen_anon_1
                .uint32
        } else {
            0
        };

        sub_ifindex = if index_get_sub_ifindex < incoming_value.len() {
            incoming_value[index_get_sub_ifindex]
                .value
                .__bindgen_anon_1
                .uint32
        } else {
            0
        };
    }

    Some(ParsedIncomingValues {
        ipv4,
        inbound,
        layer_id,
        ifindex,
        sub_ifindex,
    })
}

pub unsafe extern "C" fn notify_transport(
    _notify_type: FWPS_CALLOUT_NOTIFY_TYPE,
    _filter_key: *const GUID,
    _filter: *mut FWPS_FILTER0,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub unsafe extern "C" fn flow_delete_transport(_layer_id: u16, _callout_id: u32, _flow_context: u64) {
    // Flow cleanup if needed
}
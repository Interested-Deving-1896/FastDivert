use crate::context::Context;
use crate::ioctl_user::{DivertAddress, DivertData, DivertDataFlow, LAYER_STREAM};
use crate::log;
use crate::ringbuffer::RecordHeader;
use crate::wdk_ext::ndis::*;
use core::ptr::null_mut;
use core::slice;
use wdk_sys::{GUID, PMDL, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, NTSTATUS, HANDLE, NT_SUCCESS};

pub struct StreamLayer {
    pub inject_handle_stream: HANDLE,
    pub stream_callout_id_v4: u32,
    pub stream_callout_id_v6: u32,
}

impl StreamLayer {
    pub fn initialize() -> Result<Self, NTSTATUS> {
        unsafe {
            let mut inject_handle_stream = null_mut();

            let status = FwpsInjectionHandleCreate0(
                AF_INET as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_STREAM,
                &mut inject_handle_stream,
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }

            Ok(Self {
                inject_handle_stream,
                stream_callout_id_v4: 0,
                stream_callout_id_v6: 0,
            })
        }
    }

    pub fn inject(
        &self,
        flow_id: u64,
        is_ipv6: bool,
        is_inbound: bool,
        nbl: *mut NET_BUFFER_LIST,
        packet_len: usize,
        completion_ctx_ptr: *mut core::ffi::c_void,
    ) -> NTSTATUS {
        unsafe {
            if nbl.is_null() {
                return wdk_sys::STATUS_INSUFFICIENT_RESOURCES;
            }

            let (callout_id, layer_id) = if is_ipv6 {
                (
                    self.stream_callout_id_v6,
                    FWPS_BUILTIN_LAYERS__FWPS_LAYER_STREAM_V6 as u16,
                )
            } else {
                (
                    self.stream_callout_id_v4,
                    FWPS_BUILTIN_LAYERS__FWPS_LAYER_STREAM_V4 as u16,
                )
            };

            if self.inject_handle_stream.is_null() {
                log!("StreamLayer::inject: stream injection handle is null!");
                return wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
            }

            if callout_id == 0 {
                log!("StreamLayer::inject: callout id is 0, make sure stream callout is registered!");
                return wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
            }

            let stream_flags = if is_inbound {
                FWPS_STREAM_FLAG_RECEIVE
            } else {
                FWPS_STREAM_FLAG_SEND
            };

            let completion_fn: crate::wdk_ext::ndis::FWPS_INJECT_COMPLETE0 = Some(crate::network::inject::injection_completion_fn);

            let status = FwpsStreamInjectAsync0(
                self.inject_handle_stream,
                null_mut(), // injectionContext
                0,          // flags (reserved, must be 0)
                flow_id,
                callout_id,
                layer_id,
                stream_flags,
                nbl,
                packet_len as wdk_sys::SIZE_T,
                completion_fn,
                completion_ctx_ptr,
            );

            if !wdk::nt_success(status) {
                if let Some(comp_fn) = completion_fn {
                    comp_fn(completion_ctx_ptr, nbl, 0);
                }
                log!("FwpsStreamInject failed: {:#010X}", status);
            }

            status
        }
    }
}

impl Drop for StreamLayer {
    fn drop(&mut self) {
        unsafe {
            if !self.inject_handle_stream.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_stream);
            }
        }
    }
}

struct ParsedIncomingValues {
    ipv4: bool,
    inbound: bool,
    layer_id: u16,
}

#[inline(always)]
unsafe fn process_stream_data(
    context_ptr: &mut Context,
    stream_packet: *mut FWPS_STREAM_CALLOUT_IO_PACKET0,
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
    parsed_values: &ParsedIncomingValues,
    cpu_index: u32,
) {
    unsafe {
        if stream_packet.is_null() {
            return;
        }
        let stream_data_ptr = (*stream_packet).streamData;
        if stream_data_ptr.is_null() {
            return;
        }
        let stream_data = &*stream_data_ptr;
        let data_len = stream_data.dataLength as usize;
        if data_len == 0 {
            return;
        }

        // Get process ID
        let process_id = if !in_meta_values.is_null() {
            let meta = &*in_meta_values;
            if (meta.currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0 {
                meta.processId as u32
            } else {
                0
            }
        } else {
            0
        };

        // Determine packet direction based on stream_data flags.
        // This is 100% accurate for stream layers.
        let is_inbound_stream = (stream_data.flags & FWPS_STREAM_FLAG_RECEIVE) != 0;

        let mut bytes_copied: u64 = 0;

        let net_ctx = context_ptr.get_network_ctx_ptr();
        if !net_ctx.is_null() {
            let net_ctx_ref = &mut *net_ctx;
            if let Some(ref rb) = net_ctx_ref.ring_buffer {
                let mut addr = DivertAddress {
                    timestamp: 0,
                    flags: 0,
                    reserved2: 0,
                    data: DivertData {
                        flow: DivertDataFlow {
                            endpoint_id: 0,
                            process_id,
                            filter_id: 0,
                            layer: LAYER_STREAM as u8,
                            flags: 0,
                            reserved: [0; 6],
                        },
                    },
                };
                addr.set_layer(LAYER_STREAM as u8);
                addr.set_ipv6(!parsed_values.ipv4);
                addr.set_outbound(!is_inbound_stream);

                let packet_header = RecordHeader {
                    len: (core::mem::size_of::<DivertAddress>() + data_len) as u32,
                    _reserved: 0,
                };

                let address_bytes = core::slice::from_raw_parts(
                    &addr as *const DivertAddress as *const u8,
                    core::mem::size_of::<DivertAddress>(),
                );

                let expected_total_size = core::mem::size_of::<RecordHeader>()
                    + address_bytes.len()
                    + data_len;

                let res = rb.transaction(cpu_index, expected_total_size, |tx| {
                    tx.push_slice(&packet_header, address_bytes)?;

                    let (ptr1, len1, ptr2, len2) = tx.get_write_ptrs(data_len);

                    if len2 == 0 {
                        // Perfect case: No wrap-around! Write directly into the ring buffer with zero allocation.
                        let mut copied: u64 = 0;
                        FwpsCopyStreamDataToBuffer0(
                            stream_data_ptr,
                            ptr1 as *mut _,
                            data_len as u64,
                            &mut copied as *mut u64,
                        );
                        bytes_copied = copied;
                        tx.advance_offset(copied as usize);

                        if (copied as usize) < data_len {
                            // Zero-fill the rest to maintain exact committed size and avoid deadlocking CAS queue
                            let rem = data_len - copied as usize;
                            core::ptr::write_bytes(ptr1.add(copied as usize), 0, rem);
                            tx.advance_offset(rem);
                        }
                    } else {
                        // Wrap-around case: SPSC ring buffer write window crossed the boundary.
                        // We fallback to a temporary heap-allocated buffer. Since wrap-arounds occur extremely
                        // infrequently, the overhead is negligible.
                        let mut temp_buf = alloc::vec![0u8; data_len];
                        let mut copied: u64 = 0;
                        FwpsCopyStreamDataToBuffer0(
                            stream_data_ptr,
                            temp_buf.as_mut_ptr() as *mut _,
                            data_len as u64,
                            &mut copied as *mut u64,
                        );
                        bytes_copied = copied;
                        if copied > 0 {
                            tx.push_slice_only(&temp_buf[..copied as usize]);
                        }
                        if (copied as usize) < data_len {
                            // Pad the rest of the transaction size with zero bytes
                            let rem = data_len - copied as usize;
                            let pad_buf = alloc::vec![0u8; rem];
                            tx.push_slice_only(&pad_buf);
                        }
                    }
                    Ok(())
                });

                match res {
                    Ok(_) => {}
                    Err(status) => match status {
                        STATUS_INSUFFICIENT_RESOURCES => {
                            net_ctx_ref.metrics_inc_dropped();
                        }
                        _ => {
                            log!("rb push failed for stream data: {:#x}", status);
                        }
                    },
                }
            }
        }

        // Set the count of bytes copied so that WFP knows we've processed this data.
        (*stream_packet).countBytesEnforced = bytes_copied;
    }
}

pub unsafe extern "C" fn classify_stream(
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

    let parsed_incoming_values = match parse_incoming_values_stream(in_fixed_values) {
        Some(value) => value,
        None => {
            log!("got invalid layer in stream classifyFn, should not happen");
            return;
        }
    };

    let classify_out = unsafe { &mut *classify_out };
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
        let net_ctx = (*context_ptr).get_network_ctx_ptr();
        if !net_ctx.is_null() {
            (*net_ctx).metrics_inc_received();
        }
        // Always continue for stream monitoring to avoid disrupting TCP connections
        classify_out.actionType = FWP_ACTION_CONTINUE;
    }
}

fn have_write_right(classify_out: *const FWPS_CLASSIFY_OUT0) -> bool {
    unsafe { ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 }
}

fn parse_incoming_values_stream(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
) -> Option<ParsedIncomingValues> {
    let ipv4: bool;
    let inbound: bool;
    let layer_id = unsafe { (*in_fixed_values).layerId };
    let direction: u32;

    unsafe {
        let index_get_direction: usize;

        match (layer_id as i32) {
            FWPS_BUILTIN_LAYERS__FWPS_LAYER_STREAM_V4 => {
                ipv4 = true;
                index_get_direction = FWPS_FIELDS_STREAM_V4__FWPS_FIELD_STREAM_V4_DIRECTION as usize;
            }
            FWPS_BUILTIN_LAYERS__FWPS_LAYER_STREAM_V6 => {
                ipv4 = false;
                index_get_direction = FWPS_FIELDS_STREAM_V6__FWPS_FIELD_STREAM_V6_DIRECTION as usize;
            }
            _ => {
                return None;
            }
        }

        let incoming_value = slice::from_raw_parts_mut(
            (*in_fixed_values).incomingValue,
            (*in_fixed_values).valueCount as usize,
        );

        direction = incoming_value[index_get_direction]
            .value
            .__bindgen_anon_1
            .uint32;

        // FWP_DIRECTION__FWP_DIRECTION_INBOUND = 1
        // FWP_DIRECTION__FWP_DIRECTION_OUTBOUND = 0
        inbound = direction == FWP_DIRECTION__FWP_DIRECTION_INBOUND as u32;
    }

    Some(ParsedIncomingValues {
        ipv4,
        inbound,
        layer_id,
    })
}

pub unsafe extern "C" fn notify_stream(
    _notify_type: FWPS_CALLOUT_NOTIFY_TYPE,
    _filter_key: *const GUID,
    _filter: *mut FWPS_FILTER0,
) -> NTSTATUS {
    STATUS_SUCCESS
}

pub unsafe extern "C" fn flow_delete_stream(_layer_id: u16, _callout_id: u32, _flow_context: u64) {
    // Flow cleanup if needed
}
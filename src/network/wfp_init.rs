use crate::context::Context;
use crate::log;
use crate::network::callout_network::*;
use crate::network::callout_transport::*;
use crate::network::callout_stream::*;
use crate::network::callout_flow::*;
use crate::network::callout_socket::*;
use crate::network::guids::PROVIDER_GUID;
use crate::wdk_ext::ndis::*;
use crate::wdk_ext::wdf_wrapper::*;
use crate::MEMORY_POOL_TAG;
use alloc::format;
use alloc::vec::Vec;
use core::ptr::{addr_of_mut, null_mut};
use wdk_sys::{GUID, NTSTATUS, NT_SUCCESS, PWSTR, STATUS_SUCCESS};
use crate::ioctl_user::{LAYER_NETWORK, LAYER_NETWORK_FORWARD, LAYER_FLOW, LAYER_SOCKET, LAYER_REFLECT, LAYER_TRANSPORT, LAYER_STREAM};

/// Internal helper macro to easily create null-terminated UTF-16 wide strings.
macro_rules! wstr {
    ($s:expr) => {{
        let mut v: Vec<u16> = $s.encode_utf16().collect();
        v.push(0);
        v
    }};
}

/// Core initialization function: integrates all WFP resource configurations.
pub fn init_wfp(device: wdk_sys::WDFDEVICE, context_ptr: *mut Context) -> Result<HANDLE, NTSTATUS> {
    unsafe {
        // 1. Open WFP Engine
        let mut engine_handle: HANDLE = null_mut();
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC, // Free all resources when session ends
            ..Default::default()
        };

        let status = FwpmEngineOpen0(
            null_mut(),
            RPC_C_AUTHN_DEFAULT as u32,
            null_mut(),
            &session,
            &mut engine_handle,
        );
        if !NT_SUCCESS(status) {
            log!("init_wfp: FwpmEngineOpen0 failed: {:#010X}", status);
            return Err(status);
        }
        let net_ctx = (*context_ptr).get_network_ctx_ptr();
        if !net_ctx.is_null() {
            (*net_ctx).fwpm_engine_handle = engine_handle;
        }

        // 2. Start transaction for atomic configuration
        let status = FwpmTransactionBegin0(engine_handle, 0);
        if !NT_SUCCESS(status) {
            log!("init_wfp: FwpmTransactionBegin0 failed: {:#010X}", status);
            FwpmEngineClose0(engine_handle);
            return Err(status);
        }

        // 3. Dynamically generate and register components
        let result = (|| -> Result<(), NTSTATUS> {
            let p_name = wstr!("MyDynamicProvider");
            let provider = FWPM_PROVIDER0 {
                providerKey: PROVIDER_GUID,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: p_name.as_ptr() as PWSTR,
                    ..Default::default()
                },
                ..Default::default()
            };
            let status = FwpmProviderAdd0(engine_handle, &provider, null_mut());
            if status != STATUS_SUCCESS && status != 0xC0220009u32 as i32 {
                status.check().inspect_err(|status| log!("Failed to add provider: {:#010X}", status))?;
            }

            // Dynamically generate Sublayer GUID
            let mut sublayer_guid = GUID::default();
            wdk_sys::ntddk::ExUuidCreate(&mut sublayer_guid);

            // Store sublayer guid in context to use later if needed
            let net_ctx = (*context_ptr).get_network_ctx_ptr();
            if !net_ctx.is_null() {
                (*net_ctx).sublayer_guid = sublayer_guid;
            }

            let s_name = wstr!("MyDynamicSublayer");
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: sublayer_guid,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: s_name.as_ptr() as PWSTR,
                    ..Default::default()
                },
                providerKey: &PROVIDER_GUID as *const _ as *mut _,
                weight: 65535, // High priority
                ..Default::default()
            };
            FwpmSubLayerAdd0(engine_handle, &sublayer, null_mut())
                .check()
                .inspect_err(|status| log!("Failed to add sublayer: {:#010X}", status))?;

            // 4. Register and add Callouts and Filters
            let layer = (*context_ptr).layer;
            let mut layers = Vec::new();

            if layer == LAYER_NETWORK {
                layers.push((FWPM_LAYER_INBOUND_IPPACKET_V4, "InboundV4"));
                layers.push((FWPM_LAYER_OUTBOUND_IPPACKET_V4, "OutboundV4"));
                layers.push((FWPM_LAYER_INBOUND_IPPACKET_V6, "InboundV6"));
                layers.push((FWPM_LAYER_OUTBOUND_IPPACKET_V6, "OutboundV6"));
            } else if layer == LAYER_NETWORK_FORWARD {
                layers.push((FWPM_LAYER_IPFORWARD_V4, "ForwardV4"));
                layers.push((FWPM_LAYER_IPFORWARD_V6, "ForwardV6"));
            } else if layer == LAYER_FLOW {
                layers.push((FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, "FlowV4"));
                layers.push((FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, "FlowV6"));
            } else if layer == LAYER_SOCKET {
                layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V4, "SocketConnectV4"));
                layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V6, "SocketConnectV6"));
                // Can also add bind/listen/accept here if needed
            } else if layer == LAYER_REFLECT {
                // Placeholder for Reflect
            } else if layer == LAYER_TRANSPORT {
                layers.push((FWPM_LAYER_INBOUND_TRANSPORT_V4, "InboundTransportV4"));
                layers.push((FWPM_LAYER_OUTBOUND_TRANSPORT_V4, "OutboundTransportV4"));
                layers.push((FWPM_LAYER_INBOUND_TRANSPORT_V6, "InboundTransportV6"));
                layers.push((FWPM_LAYER_OUTBOUND_TRANSPORT_V6, "OutboundTransportV6"));
            } else if layer == LAYER_STREAM {
                layers.push((FWPM_LAYER_STREAM_V4, "StreamV4"));
                layers.push((FWPM_LAYER_STREAM_V6, "StreamV6"));
            }

            for (i, (layer_guid, name_str)) in layers.iter().enumerate() {
                let mut callout_guid = GUID::default();
                wdk_sys::ntddk::ExUuidCreate(&mut callout_guid);

                // Kernel-mode callout registration
                let reg_callout = FWPS_CALLOUT0 {
                    calloutKey: callout_guid,
                    classifyFn: if layer == LAYER_TRANSPORT {
                        Some(classify_transport)
                    } else if layer == LAYER_STREAM {
                        Some(classify_stream)
                    } else if layer == LAYER_FLOW {
                        Some(classify_flow)
                    } else if layer == LAYER_SOCKET {
                        Some(classify_socket)
                    } else {
                        Some(classify_network)
                    },
                    notifyFn: if layer == LAYER_TRANSPORT {
                        Some(notify_transport)
                    } else if layer == LAYER_STREAM {
                        Some(notify_stream)
                    } else if layer == LAYER_FLOW {
                        Some(notify_flow)
                    } else if layer == LAYER_SOCKET {
                        Some(notify_socket)
                    } else {
                        Some(notify_network)
                    },
                    flowDeleteFn: if layer == LAYER_TRANSPORT {
                        Some(flow_delete_transport)
                    } else if layer == LAYER_STREAM {
                        Some(flow_delete_stream)
                    } else if layer == LAYER_FLOW {
                        Some(flow_delete_flow)
                    } else if layer == LAYER_SOCKET {
                        Some(flow_delete_socket)
                    } else {
                        Some(flow_delete_network)
                    },
                    ..Default::default()
                };
                let mut registered_callout_id: u32 = 0;
                FwpsCalloutRegister0(
                    WdfDeviceWdmGetDeviceObject(device) as *mut _,
                    &reg_callout,
                    &mut registered_callout_id,
                )
                .check()
                .inspect_err(|status| log!("Failed to register callout: {:#010X}", status))?;

                let net_ctx = (*context_ptr).get_network_ctx_ptr();
                if !net_ctx.is_null() {
                    let net_ctx_ref = &mut *net_ctx;
                    if layer == LAYER_STREAM {
                        if let crate::network::context::WfpLayer::Stream(ref mut stream_layer) = net_ctx_ref.active_layer {
                            if i == 0 {
                                stream_layer.stream_callout_id_v4 = registered_callout_id;
                                log!("Registered StreamV4 callout runtime ID: {}", registered_callout_id);
                            } else if i == 1 {
                                stream_layer.stream_callout_id_v6 = registered_callout_id;
                                log!("Registered StreamV6 callout runtime ID: {}", registered_callout_id);
                            }
                        }
                    }
                }

                // Management-plane callout registration
                let c_name = wstr!(format!("Callout_{}", name_str));
                let m_callout = FWPM_CALLOUT0 {
                    calloutKey: callout_guid,
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: c_name.as_ptr() as PWSTR,
                        ..Default::default()
                    },
                    applicableLayer: *layer_guid,
                    providerKey: &PROVIDER_GUID as *const _ as *mut _,
                    ..Default::default()
                };
                FwpmCalloutAdd0(engine_handle, &m_callout, null_mut(), null_mut())
                    .check()
                    .inspect_err(|status| log!("Failed to add callout: {:#010X}", status))?;

                // Add Filter and bind Context
                let f_name = wstr!(format!("Filter_{}", name_str));
                let mut filter_id: u64 = 0;
                let mut weight_val = (i + 1) as u64;

                // TODO: add filter conditions based on compiler output

                let filter = FWPM_FILTER0 {
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: f_name.as_ptr() as PWSTR,
                        ..Default::default()
                    },
                    layerKey: *layer_guid,
                    subLayerKey: sublayer_guid,
                    providerKey: &PROVIDER_GUID as *const _ as *mut _,
                    weight: FWP_VALUE0 {
                        type_: FWP_DATA_TYPE__FWP_UINT64,
                        __bindgen_anon_1: FWP_VALUE0___bindgen_ty_1 {
                            uint64: addr_of_mut!(weight_val) as *mut _,
                        },
                    },
                    action: FWPM_ACTION0 {
                        type_: FWP_ACTION_CALLOUT_UNKNOWN,
                        __bindgen_anon_1: FWPM_ACTION0___bindgen_ty_1 {
                            calloutKey: core::mem::ManuallyDrop::new(callout_guid),
                        },
                    },
                    __bindgen_anon_1: FWPM_FILTER0___bindgen_ty_1 {
                        rawContext: core::mem::ManuallyDrop::new(context_ptr as u64),
                    },
                    ..Default::default()
                };

                FwpmFilterAdd0(engine_handle, &filter, null_mut(), &mut filter_id)
                    .check()
                    .inspect_err(|status| log!("Failed to add filter: {:#010X}", status))?;

                let net_ctx = (*context_ptr).get_network_ctx_ptr();
                if !net_ctx.is_null() {
                    (*net_ctx).filter_ids.push(filter_id);
                }
            }

            Ok(())
        })();

        // 5. Commit or rollback transaction
        if result.is_ok() {
            FwpmTransactionCommit0(engine_handle)
                .check()
                .inspect_err(|_| log!("Failed to commit transaction"))?;
            log!("WFP initialization completed successfully");
        } else {
            FwpmTransactionAbort0(engine_handle);
            log!("WFP init failed, aborted transaction");
            return Err(result.unwrap_err());
        }

        Ok(engine_handle)
    }
}

/// De-initialization function: Cleans up all WFP resources
pub fn uninit_wfp(engine_h: HANDLE, context_ptr: *mut Context) {
    unsafe {
        if engine_h.is_null() {
            return;
        }

        log!("Starting de-initialization of WFP resources...");

        // 1. Delete filters (using the IDs stored in the context)
        if !context_ptr.is_null() {
            let net_ctx = (*context_ptr).get_network_ctx_ptr();
            if !net_ctx.is_null() {
                for filter_id in &(*net_ctx).filter_ids {
                    if *filter_id != 0 {
                        FwpmFilterDeleteById0(engine_h, *filter_id);
                    }
                }
            }
        }

        // Note: Because FWPM_SESSION_FLAG_DYNAMIC was used during initialization,
        // most management-plane objects (Callout, Sublayer, Provider, Filter)
        // will be automatically cleaned up by the system when the engine handle is closed.
        // However, explicitly deleting them is a good practice.

        // 2. Unregister kernel mode callouts
        // Note: Ideally, callout IDs should be stored to use FwpsCalloutUnregisterById0.
        // Here, it relies on automatic cleanup on engine close.

        // 3. Close WFP engine handle
        FwpmEngineClose0(engine_h);

        log!("WFP resource cleanup finished");
    }
}

/// Helper trait to simplify NTSTATUS checking
trait StatusExt {
    fn check(self) -> Result<(), NTSTATUS>;
}

impl StatusExt for NTSTATUS {
    fn check(self) -> Result<(), NTSTATUS> {
        if NT_SUCCESS(self) { Ok(()) } else { Err(self) }
    }
}

/// Maintains the original NDIS pool initialization logic, removed redundancies
pub fn initialize_ndis_pools() -> (NDIS_HANDLE, NDIS_HANDLE, NTSTATUS) {
    unsafe {
        let nbl_params = NET_BUFFER_LIST_POOL_PARAMETERS {
            Header: NDIS_OBJECT_HEADER {
                Type: NDIS_OBJECT_TYPE_DEFAULT as u8,
                Revision: NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 as u8,
                Size: core::mem::size_of::<NET_BUFFER_LIST_POOL_PARAMETERS>() as u16,
            },
            fAllocateNetBuffer: 1,
            PoolTag: MEMORY_POOL_TAG,
            ..Default::default()
        };
        let nbl_pool = NdisAllocateNetBufferListPool(null_mut(), &nbl_params);

        let nb_params = NET_BUFFER_POOL_PARAMETERS {
            Header: NDIS_OBJECT_HEADER {
                Type: NDIS_OBJECT_TYPE_DEFAULT as u8,
                Revision: NET_BUFFER_POOL_PARAMETERS_REVISION_1 as u8,
                Size: core::mem::size_of::<NET_BUFFER_POOL_PARAMETERS>() as u16,
            },
            PoolTag: MEMORY_POOL_TAG,
            ..Default::default()
        };
        let nb_pool = NdisAllocateNetBufferPool(null_mut(), &nb_params);

        if nbl_pool.is_null() || nb_pool.is_null() {
            return (
                null_mut(),
                null_mut(),
                wdk_sys::STATUS_INSUFFICIENT_RESOURCES,
            );
        }
        (nbl_pool, nb_pool, STATUS_SUCCESS)
    }
}

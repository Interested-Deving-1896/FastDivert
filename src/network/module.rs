//! Network-specific driver module implementation

extern crate alloc;
use alloc::boxed::Box;
use core::ptr::null_mut;
use wdk_sys::{NTSTATUS, WDFREQUEST, STATUS_SUCCESS, STATUS_INVALID_DEVICE_REQUEST, STATUS_PENDING, STATUS_INSUFFICIENT_RESOURCES, STATUS_BUFFER_TOO_SMALL};
use wdk_sys::ntddk::{IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool};

use crate::context::Context;
use crate::ioctl_internal::IoctlMMapResponse;
use crate::ioctl_user::{LAYER_FLOW, LAYER_SOCKET, DivertAddress, Flags};
use crate::network::context::NetworkContext;
use crate::network::bpf::BpfInsn;
use crate::network::inject::{UserInjectionCompletionContext, allocate_nbl_from_mdl};
use crate::network::wfp_init::{init_wfp, uninit_wfp};
use crate::log;

/// Packet arrived notification callback, registered in the SPSC ring buffer.
/// Wakes up any pending IOCTL_RECV requests on the file object's recv queue.
pub unsafe extern "C" fn packet_arrived_callback(ctx_ptr: *mut core::ffi::c_void) {
    if ctx_ptr.is_null() {
        return;
    }
    unsafe {
        let ctx = ctx_ptr as *mut Context;
        let queue = (*ctx).recv_queue;

        let mut request: wdk_sys::WDFREQUEST = null_mut();
        while crate::wdk_ext::wdf_wrapper::WdfIoQueueRetrieveNextRequest(queue, &mut request) == STATUS_SUCCESS && !request.is_null() {
            crate::wdk_ext::wdf_wrapper::WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, 0);
            request = null_mut();
        }
    }
}

pub struct NetworkModule {
    pub network_ctx: NetworkContext,
    pub bpf_program: alloc::vec::Vec<BpfInsn>,
}

unsafe impl Send for NetworkModule {}
unsafe impl Sync for NetworkModule {}

impl NetworkModule {
    /// Creates and initializes a new NetworkModule
    pub fn new(layer: u32) -> Result<Self, NTSTATUS> {
        let mut network_ctx = NetworkContext::new()?;
        network_ctx.initialize(layer)?;
        Ok(Self {
            network_ctx,
            bpf_program: alloc::vec::Vec::new(),
        })
    }
}

impl NetworkModule {
    pub fn startup(&mut self, ctx_ptr: *mut Context, flags: u64) -> Result<(), NTSTATUS> {
        log!("NetworkModule::startup: registering WFP filters with flags {:#010X}", flags);
        unsafe {
            let ctx = &mut *ctx_ptr;
            match init_wfp(ctx.device, ctx_ptr) {
                Ok(engine_h) => {
                    ctx.flags = flags;
                    self.network_ctx.fwpm_engine_handle = engine_h;

                    if (flags & (Flags::RecvOnly as u64)) != 0 {
                        self.network_ctx.packet_read_only = true;
                    }
                    Ok(())
                }
                Err(status) => {
                    log!("NetworkModule::startup failed: {:#010X}", status);
                    Err(status)
                }
            }
        }
    }

    pub fn map_memory(&self) -> Result<IoctlMMapResponse, NTSTATUS> {
        unsafe {
            // Handle ALE layers (Socket, Flow)
            if let Some(ref ale_rb) = self.network_ctx.ale_ring_buffer {
                let (recv_header, recv_data) = match ale_rb.map_to_user_space() {
                    Ok(map_result) => map_result,
                    Err(err) => {
                        log!("NetworkModule::map_memory: failed to map ALE ring buffer");
                        return Err(err);
                    }
                };

                return Ok(IoctlMMapResponse {
                    max_cores: 1,
                    size: 2 * 1024 * 1024,
                    ring_buffer_header: recv_header,
                    ring_buffer_data: recv_data,
                    send_ring_buffer_header: null_mut(),
                    send_ring_buffer_data: null_mut(),
                });
            }

            // Handle Standard Network layers (Network, Transport, etc.)
            if let Some(per_cpu_rb) = &self.network_ctx.ring_buffer {
                let (recv_header, recv_data) = match per_cpu_rb.map_to_user_space() {
                    Ok(map_result) => map_result,
                    Err(err) => {
                        log!("NetworkModule::map_memory: failed to map receive ring buffer");
                        return Err(err);
                    }
                };

                Ok(IoctlMMapResponse {
                    max_cores: per_cpu_rb.workers_num(),
                    size: per_cpu_rb.get_ring_buffer_size() as u32,
                    ring_buffer_header: recv_header,
                    ring_buffer_data: recv_data,
                    send_ring_buffer_header: null_mut(),
                    send_ring_buffer_data: null_mut(),
                })
            } else {
                log!("NetworkModule::map_memory: SPSC ring buffers are not initialized");
                Err(STATUS_INVALID_DEVICE_REQUEST)
            }
        }
    }

    pub fn arm_recv(&self, ctx_ptr: *mut Context) -> Result<(), NTSTATUS> {
        unsafe {
            let ctx = &*ctx_ptr;
            let queue = ctx.recv_queue;

            // Flow or Socket layer
            if ctx.layer == LAYER_FLOW || ctx.layer == LAYER_SOCKET {
                if let Some(ref rb) = self.network_ctx.ale_ring_buffer {
                    rb.set_notify_callback(
                        Some(packet_arrived_callback),
                        ctx_ptr as *mut core::ffi::c_void,
                    );
                    rb.set_watching();
                } else {
                    return Err(STATUS_INVALID_DEVICE_REQUEST);
                }
            } else {
                // SPSC Packet layers
                if let Some(ref rb) = self.network_ctx.ring_buffer {
                    rb.set_notify_callback(
                        Some(packet_arrived_callback),
                        ctx_ptr as *mut core::ffi::c_void,
                    );
                    rb.set_watching();

                    // Double check to prevent race condition
                    if rb.has_unread_packets() {
                        if rb.test_and_clear_watching_flag() {
                            let mut out_req: wdk_sys::WDFREQUEST = null_mut();
                            while crate::wdk_ext::wdf_wrapper::WdfIoQueueRetrieveNextRequest(queue, &mut out_req) == STATUS_SUCCESS && !out_req.is_null() {
                                crate::wdk_ext::wdf_wrapper::WdfRequestCompleteWithInformation(out_req, STATUS_SUCCESS, 0);
                                out_req = null_mut();
                            }
                        }
                    }
                } else {
                    return Err(STATUS_INVALID_DEVICE_REQUEST);
                }
            }
            Ok(())
        }
    }

    pub fn handle_send(&self, ctx_ptr: *mut Context, request: WDFREQUEST, input_buffer_len: usize) -> NTSTATUS {
        unsafe {

            // Retrieve Single Packet Input Buffer
            let mut buffer_ptr: wdk_sys::PVOID = null_mut();
            let mut buffer_length: usize = 0;

            let status = crate::wdk_ext::wdf_wrapper::WdfRequestRetrieveInputBuffer(
                request,
                core::mem::size_of::<DivertAddress>(),
                &mut buffer_ptr,
                &mut buffer_length,
            );

            if !wdk::nt_success(status) || buffer_ptr.is_null() {
                log!("NetworkModule::handle_send: WdfRequestRetrieveInputBuffer failed {:#010X}", status);
                return status;
            }

            if buffer_length < core::mem::size_of::<DivertAddress>() {
                log!("NetworkModule::handle_send: buffer too small");
                return STATUS_BUFFER_TOO_SMALL;
            }

            let addr = &*(buffer_ptr as *const DivertAddress);
            let packet_len = buffer_length - core::mem::size_of::<DivertAddress>();

            if packet_len == 0 {
                log!("NetworkModule::handle_send: packet length is 0");
                return STATUS_INVALID_DEVICE_REQUEST;
            }

            let packet_data_offset = core::mem::size_of::<DivertAddress>();

            // Allocate MDL for user buffer
            let mdl = IoAllocateMdl(
                buffer_ptr,
                buffer_length as u32,
                0, // SecondaryBuffer
                0, // ChargeQuota
                null_mut(),
            );

            if mdl.is_null() {
                log!("NetworkModule::handle_send: IoAllocateMdl failed");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // Build MDL for non-paged pool buffer
            wdk_sys::ntddk::MmBuildMdlForNonPagedPool(mdl);

            // Allocate Completion Context
            let completion_ctx_ptr = wdk_sys::ntddk::ExAllocatePool2(
                wdk_sys::POOL_FLAG_NON_PAGED,
                core::mem::size_of::<UserInjectionCompletionContext>() as u64,
                u32::from_be_bytes(*b"UICx"),
            ) as *mut UserInjectionCompletionContext;

            if completion_ctx_ptr.is_null() {
                IoFreeMdl(mdl);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            (*completion_ctx_ptr).mdl = mdl;
            (*completion_ctx_ptr).request = request;

            // Construct NetBufferList from MDL
            let nbl = match allocate_nbl_from_mdl(
                null_mut(),
                mdl,
                packet_data_offset,
                packet_len,
            ) {
                Some(n) => n,
                None => {
                    wdk_sys::ntddk::ExFreePoolWithTag(completion_ctx_ptr as *mut _, u32::from_be_bytes(*b"UICx"));
                    IoFreeMdl(mdl);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            };

            // Inject NBL into Windows Filtering Platform using the structural active layer's inject method
            let inject_status = match &self.network_ctx.active_layer {
                crate::network::context::WfpLayer::Network(layer) => {
                    layer.inject(
                        !addr.outbound(),
                        addr.ipv6(),
                        addr.data.network.if_idx,
                        addr.data.network.sub_if_idx,
                        nbl,
                        completion_ctx_ptr as *mut _,
                    )
                }
                crate::network::context::WfpLayer::Forward(layer) => {
                    layer.inject(
                        !addr.outbound(),
                        addr.ipv6(),
                        addr.data.network.if_idx,
                        addr.data.network.sub_if_idx,
                        nbl,
                        completion_ctx_ptr as *mut _,
                    )
                }
                crate::network::context::WfpLayer::Transport(layer) => {
                    layer.inject(
                        !addr.outbound(),
                        addr.ipv6(),
                        addr.data.network.if_idx,
                        addr.data.network.sub_if_idx,
                        nbl,
                        completion_ctx_ptr as *mut _,
                    )
                }
                crate::network::context::WfpLayer::Stream(layer) => {
                    layer.inject(
                        addr.data.flow.endpoint_id,
                        addr.ipv6(),
                        !addr.outbound(),
                        nbl,
                        packet_len,
                        completion_ctx_ptr as *mut _,
                    )
                }
                _ => {
                    log!("NetworkModule::handle_send: active layer cannot inject!");
                    crate::network::inject::injection_completion_fn(completion_ctx_ptr as *mut _, nbl, 0);
                    wdk_sys::STATUS_INVALID_PARAMETER
                }
            };

            if !wdk::nt_success(inject_status) {
                log!("NetworkModule::handle_send: inject_nbl failed {:#010X}", inject_status);
                return STATUS_PENDING; // Completion callback completes request
            }

            STATUS_PENDING
        }
    }

    pub fn cleanup(&mut self, ctx_ptr: *mut Context) {
        log!("NetworkModule::cleanup: tearing down WFP and SPSC ring buffers");
        unsafe {
            // Teardown WFP registration
            uninit_wfp(self.network_ctx.fwpm_engine_handle, ctx_ptr);
            self.network_ctx.filter_ids.clear();

            // Clear callbacks and watching on packet ring buffer
            if let Some(ref rb) = self.network_ctx.ring_buffer {
                rb.set_notify_callback(None, null_mut());
                rb.clear_watching();
            }

            // Clear callbacks and watching on ALE ring buffer
            if let Some(ref ale_rb) = self.network_ctx.ale_ring_buffer {
                ale_rb.set_notify_callback(None, null_mut());
                ale_rb.clear_watching();
            }
        }
    }
}

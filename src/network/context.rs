/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

extern crate alloc;
use crate::context::Context;
use crate::ioctl_user::{
    LAYER_FLOW, LAYER_SOCKET, LAYER_NETWORK, LAYER_NETWORK_FORWARD, LAYER_TRANSPORT, LAYER_STREAM,
};
use crate::ringbuffer::{LockedRingBuffer, PerCpuRingBuffer};
use crate::network::callout_network::{NetworkLayer, ForwardLayer};
use crate::network::callout_transport::TransportLayer;
use crate::network::callout_stream::StreamLayer;
use crate::log;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::null_mut;
use wdk_sys::{GUID, HANDLE, NTSTATUS, NT_SUCCESS, STATUS_INSUFFICIENT_RESOURCES};

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Metrics {
    /// kernel dropped packets due to consumer too slow
    pub dropped: u64,
    /// kernel received packets
    pub received: u64,
    /// kernel injected packets
    pub sent: u64,
}

pub enum WfpLayer {
    None,
    Network(NetworkLayer),
    Forward(ForwardLayer),
    Transport(TransportLayer),
    Stream(StreamLayer),
    Flow,
    Socket,
}

impl Default for WfpLayer {
    fn default() -> Self {
        WfpLayer::None
    }
}

#[repr(C)]
pub struct NetworkContext {
    pub fwpm_engine_handle: HANDLE,
    pub sublayer_guid: GUID,

    pub active_layer: WfpLayer,

    pub packet_read_only: bool,

    pub filter_ids: Vec<u64>,

    pub ring_buffer: Option<Box<PerCpuRingBuffer>>,
    pub ale_ring_buffer: Option<Box<LockedRingBuffer>>, // For ALE events

    pub metrics: Metrics,
}

impl Default for NetworkContext {
    fn default() -> Self {
        Self {
            fwpm_engine_handle: null_mut(),
            sublayer_guid: GUID::default(),
            active_layer: WfpLayer::None,
            packet_read_only: false,
            filter_ids: Vec::new(),
            ring_buffer: None,
            ale_ring_buffer: None,
            metrics: Metrics::default(),
        }
    }
}

impl NetworkContext {
    pub fn new() -> Result<Self, NTSTATUS> {
        Ok(Self::default())
    }

    pub fn initialize(&mut self, layer: u32) -> Result<(), NTSTATUS> {
        // Create ring buffer instance for this context (2MB per core)
        let ring_buffer_size = 2 * 1024 * 1024;

        if layer == LAYER_FLOW || layer == LAYER_SOCKET {
            match LockedRingBuffer::allocate(ring_buffer_size) {
                Err(status) => {
                    log!("LockedRingBuffer::allocate failed for new context");
                    return Err(status);
                }
                Ok(prb) => {
                    self.ale_ring_buffer = Some(prb);
                }
            }
            if layer == LAYER_FLOW {
                self.active_layer = WfpLayer::Flow;
            } else {
                self.active_layer = WfpLayer::Socket;
            }
        } else {
            match PerCpuRingBuffer::allocate(ring_buffer_size, 0) {
                Err(status) => {
                    log!("PerCpuRingBuffer::new for recv failed for new context");
                    return Err(status);
                }
                Ok(prb) => {
                    self.ring_buffer = Some(prb);
                }
            }

            // Initialize the corresponding WfpLayer concrete struct
            if layer == LAYER_NETWORK {
                self.active_layer = WfpLayer::Network(NetworkLayer::initialize()?);
            } else if layer == LAYER_NETWORK_FORWARD {
                self.active_layer = WfpLayer::Forward(ForwardLayer::initialize()?);
            } else if layer == LAYER_TRANSPORT {
                self.active_layer = WfpLayer::Transport(TransportLayer::initialize()?);
            } else if layer == LAYER_STREAM {
                self.active_layer = WfpLayer::Stream(StreamLayer::initialize()?);
            }
        }

        Ok(())
    }

    pub fn metrics_reset(&mut self) {
        self.metrics.dropped = 0;
        self.metrics.received = 0;
        self.metrics.sent = 0;
    }

    #[inline(always)]
    pub fn metrics_inc_dropped(&mut self) {
        self.metrics.dropped += 1;
    }
    #[inline(always)]
    pub fn metrics_inc_received(&mut self) {
        self.metrics.received += 1;
    }
    #[inline(always)]
    pub fn metrics_inc_sent(&mut self) {
        self.metrics.sent += 1;
    }
    #[inline(always)]
    pub fn metrics_get(&self) -> Metrics {
        self.metrics
    }
}

impl Drop for NetworkContext {
    fn drop(&mut self) {
        // active_layer, ring_buffer, ale_ring_buffer will be automatically dropped via RAII
    }
}
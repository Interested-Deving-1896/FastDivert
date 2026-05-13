/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

extern crate alloc;
use crate::context::Context;
use crate::ioctl_user::Flags;
use crate::ringbuffer::PerCpuRingBuffer;
use crate::wdk_ext::ndis::{
    FwpsInjectionHandleCreate0, FwpsInjectionHandleDestroy0, ADDRESS_FAMILY, AF_INET, AF_INET6,
    FWPS_INJECTION_TYPE_FORWARD, FWPS_INJECTION_TYPE_NETWORK,
};
use crate::{log, network};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::null_mut;
use wdk_sys::{GUID, HANDLE, NTSTATUS, NT_SUCCESS, STATUS_INSUFFICIENT_RESOURCES};

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Metrics {
    /// kernel dropped packets due to consumer too slow
    dropped: u64,
    /// kernel received packets
    received: u64,
    /// kernel injected packets
    sent: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct NetworkContext {
    pub fwpm_engine_handle: HANDLE,
    pub sublayer_guid: GUID,

    pub inject_handle_in_v4: HANDLE, //todo
    pub inject_handle_out_v4: HANDLE,
    pub inject_handle_forward_v4: HANDLE,
    pub inject_handle_in_v6: HANDLE,
    pub inject_handle_out_v6: HANDLE,
    pub inject_handle_forward_v6: HANDLE,

    pub packet_read_only: bool,

    pub filter_ids: Vec<u64>,

    pub ring_buffer: *mut PerCpuRingBuffer,
    pub send_ring_buffer: *mut PerCpuRingBuffer,

    pub metrics: Metrics,
}

impl NetworkContext {
    pub fn new() -> Result<Self, NTSTATUS> {
        let mut ctx = Self::default();
        Self::initialize_injection_handles(&mut ctx)
            .inspect_err(|status| log!("initialize_injection_handles failed: {:#010X}", status))?;
        Ok(ctx)
    }

    pub fn initialize(&mut self) -> Result<(), NTSTATUS> {
        // Create ring buffer instance for this context (2MB per core)
        let ring_buffer_size = 2 * 1024 * 1024;

        match PerCpuRingBuffer::allocate(ring_buffer_size, 0) {
            Err(status) => {
                log!("PerCpuRingBuffer::new for recv failed for new context");
                return Err(status);
            }
            Ok(prb) => {
                self.ring_buffer = Box::into_raw(prb);
            }
        }

        match PerCpuRingBuffer::allocate(ring_buffer_size, 1) {
            Err(status) => {
                log!("PerCpuRingBuffer::new for send failed for new context");
                // Avoid memory leak by freeing the already allocated recv buffer
                unsafe {
                    let _ = Box::from_raw(self.ring_buffer);
                    self.ring_buffer = core::ptr::null_mut();
                }
                return Err(status);
            }
            Ok(prb) => {
                self.send_ring_buffer = Box::into_raw(prb);
            }
        }

        Ok(())
    }

    pub fn startup(&mut self, ctx_ptr: *mut Context, flags: u64) -> Result<(), NTSTATUS> {
        log!("initing wfp");
        match network::wfp_init::init_wfp(unsafe { (*ctx_ptr).device }, ctx_ptr) {
            Ok(engine_h) => unsafe {
                (*ctx_ptr).flags = flags;
                (*ctx_ptr).network_ctx.fwpm_engine_handle = engine_h;

                if flags & (Flags::RecvOnly as u64) != 0 {
                    (*ctx_ptr).network_ctx.packet_read_only = true;
                }
                Ok(())
            },
            Err(status) => {
                log!("init wfp failed: {:#010X}", status);
                Err(status)
            }
        }
    }

    pub fn initialize_injection_handles(context: &mut Self) -> Result<(), NTSTATUS> {
        unsafe {
            let status = FwpsInjectionHandleCreate0(
                AF_INET as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
                core::ptr::addr_of_mut!(context.inject_handle_forward_v4),
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET6 as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
                core::ptr::addr_of_mut!(context.inject_handle_forward_v6),
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK,
                core::ptr::addr_of_mut!(context.inject_handle_in_v4),
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK,
                core::ptr::addr_of_mut!(context.inject_handle_out_v4),
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET6 as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK,
                core::ptr::addr_of_mut!(context.inject_handle_in_v6),
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }

            let status = FwpsInjectionHandleCreate0(
                AF_INET6 as ADDRESS_FAMILY,
                FWPS_INJECTION_TYPE_NETWORK,
                core::ptr::addr_of_mut!(context.inject_handle_out_v6),
            );
            if !NT_SUCCESS(status) {
                return Err(status);
            }
        }
        Ok(())
    }

    pub fn uninit_injection_handles(&mut self) {
        unsafe {
            // Destroy injection handles
            if !self.inject_handle_forward_v4.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_forward_v4);
                self.inject_handle_forward_v4 = null_mut();
            }
            if !self.inject_handle_forward_v6.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_forward_v6);
                self.inject_handle_forward_v6 = null_mut();
            }
            if !self.inject_handle_in_v4.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_in_v4);
                self.inject_handle_in_v4 = null_mut();
            }
            if !self.inject_handle_out_v4.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_out_v4);
                self.inject_handle_out_v4 = null_mut();
            }
            if !self.inject_handle_in_v6.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_in_v6);
                self.inject_handle_in_v6 = null_mut();
            }
            if !self.inject_handle_out_v6.is_null() {
                FwpsInjectionHandleDestroy0(self.inject_handle_out_v6);
                self.inject_handle_out_v6 = null_mut();
            }
        }
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
        self.uninit_injection_handles();
        unsafe {
            if !self.ring_buffer.is_null() {
                let _ = Box::from_raw(self.ring_buffer);
                self.ring_buffer = null_mut();
            }
            if !self.send_ring_buffer.is_null() {
                let _ = Box::from_raw(self.send_ring_buffer);
                self.send_ring_buffer = null_mut();
            }
        }
    }
}
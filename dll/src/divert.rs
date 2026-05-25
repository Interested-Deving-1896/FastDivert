/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::driver_install::uninstall_driver;
use crate::ioctl_code::DivertIoctlMMapRequest;
use crate::bpf_compiler::BpfInsn;
use crate::raw::{
    open_handle, poll_cores, poll_multi_threads, recv, recv_ref, recv_ref_for_core, send,
    send_data, wait_for_data, SharedState, set_bpf_filter,
};
use crate::{
    DivertAddress, PacketRef, PacketData, RingBufferClient, DEFAULT_DRIVER_NAME, DEFAULT_DRIVER_PATH,
};
use anyhow::Context;
use std::sync::Arc;
use std::thread;

/// Internal state shared across Divert clones.
struct DivertInner {
    shared: SharedState,
}

/// Ensure the Windows handle is closed when the last reference is dropped.
impl Drop for DivertInner {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.shared.handle());
        }
    }
}

/// A Divert handle providing access to the kernel-mode driver and its ring buffer.
/// This struct is thread-safe and can be cloned to share the same driver instance.
#[derive(Clone)]
pub struct Divert {
    inner: Arc<DivertInner>,
}

/// Safety: The Windows Divert handle is thread-safe for overlapping operations
/// and IOCTLs, and our RingBufferClient is designed for concurrent access.
unsafe impl Send for DivertInner {}
unsafe impl Sync for DivertInner {}

impl Divert {
    /// Opens a divert object with a filter, attempting to connect to an existing driver instance.
    pub fn open(filter: &str, layer: u32, priority: u32, flags: u64) -> anyhow::Result<Self> {
        Divert::open_with_driver_path(
            filter,
            DEFAULT_DRIVER_NAME,
            DEFAULT_DRIVER_PATH,
            layer,
            priority,
            flags,
        )
    }

    /// Opens a divert object with a specific driver path, installing it if necessary.
    pub fn open_with_driver_path(
        filter: &str,
        driver_name: &str,
        driver_path: &str,
        layer: u32,
        priority: u32,
        flags: u64,
    ) -> anyhow::Result<Self> {
        let handle = open_handle(filter, driver_name, driver_path, layer, priority, flags)?;
        let rb_client =
            RingBufferClient::new(handle).context("Failed to initialize RingBuffer client")?;

        Ok(Self {
            inner: Arc::new(DivertInner {
                shared: SharedState::new(handle, rb_client),
            }),
        })
    }

    /// Opens a divert object with a custom mmap configuration.
    pub fn open_with_config(
        filter: &str,
        driver_name: &str,
        driver_path: &str,
        layer: u32,
        priority: u32,
        flags: u64,
        max_worker_threads: u32,
    ) -> anyhow::Result<Self> {
        let handle = open_handle(filter, driver_name, driver_path, layer, priority, flags)?;
        let rb_client = RingBufferClient::new_with_config(
            handle,
            DivertIoctlMMapRequest {
                max_cores: max_worker_threads,
            },
        )
        .context("Failed to initialize RingBuffer client")?;

        Ok(Self {
            inner: Arc::new(DivertInner {
                shared: SharedState::new(handle, rb_client),
            }),
        })
    }

    /// Uninstalls the driver service.
    pub fn uninstall(driver_name: &str) -> anyhow::Result<()> {
        uninstall_driver(driver_name).context("Failed to uninstall driver")
    }

    /// Returns the underlying shared state containing the handle and ring buffer client.
    /// This is useful for passing to functions in the `raw` module or to custom threads.
    pub fn shared_state(&self) -> SharedState {
        self.inner.shared.clone()
    }

    /// Sends a packet back into the network stack via the driver.
    pub fn send(&self, addr: &DivertAddress, data: &[u8]) -> anyhow::Result<()> {
        send(self.inner.shared.rb_client(), addr, data)
    }

    /// Sends zero-copy/wrapped packet data back into the network stack.
    pub fn send_data(&self, addr: &DivertAddress, data: &PacketData<'_>) -> anyhow::Result<()> {
        send_data(self.inner.shared.rb_client(), addr, data)
    }

    /// Directly forwards or re-injects a captured packet reference zero-copy.
    pub fn send_packet(&self, packet: &PacketRef<'_>) -> anyhow::Result<()> {
        self.send_data(&packet.address, &packet.data)
    }

    /// Receives a packet from the driver, copying the data into the provided buffer.
    /// Return the length of the written data.
    pub fn recv(&self, buffer: &mut [u8]) -> anyhow::Result<Option<usize>> {
        recv(self.inner.shared.rb_client(), buffer)
    }

    /// Receives a packet and passes its reference to the provided closure.
    pub fn recv_ref<F>(&self, callback: F) -> bool
    where
        F: FnOnce(PacketRef<'_>),
    {
        recv_ref(self.inner.shared.rb_client(), callback)
    }

    /// Receives a packet from a specific core and passes its reference to the provided closure.
    pub fn recv_ref_for_core<F>(&self, core: u32, callback: F) -> bool
    where
        F: FnOnce(PacketRef<'_>),
    {
        recv_ref_for_core(self.inner.shared.rb_client(), core, callback)
    }

    /// Blocks until the driver indicates that new packet data is available in the ring buffer.
    pub fn wait_for_data(&self) -> anyhow::Result<()> {
        wait_for_data(self.inner.shared.handle())
    }

    pub fn set_bpf_filter(&self, insns: &[BpfInsn]) -> anyhow::Result<()> {
        set_bpf_filter(self.inner.shared.handle(), insns)
    }

    /// Polls for packets in the current thread and invokes the callback for each one.
    /// Returns an error if the driver connection is lost.
    pub fn poll<F, N>(&self, mut callback: F, mut no_packet_callback: N) -> anyhow::Result<()>
    where
        F: FnMut(PacketRef<'_>),
        N: FnMut(),
    {
        loop {
            if recv_ref(self.inner.shared.rb_client(), &mut callback) {
                continue;
            }
            no_packet_callback();
        }
    }

    /// Polls for packets continuously for specific cores in the current thread.
    /// This can be used in user-managed threads to poll for specific cores.
    pub fn poll_cores<F, N>(&self, cores: &[u32], callback: F, no_packet_callback: N) -> anyhow::Result<()>
    where
        F: FnMut(PacketRef<'_>),
        N: FnMut(),
    {
        poll_cores(self.inner.shared.clone(), cores, callback, no_packet_callback)
    }

    /// Spawns multiple threads to poll for packets. Each thread monitors a subset of CPU cores.
    /// Returns the JoinHandles for the spawned threads.
    pub fn poll_multi_threads<F, N>(
        &self,
        num_threads: u32,
        callback: F,
        no_packet_callback: N,
    ) -> Vec<thread::JoinHandle<()>>
    where
        F: Fn(u32, PacketRef<'_>) + Send + Sync + Clone + 'static,
        N: FnMut() + Send + Sync + Clone + 'static,
    {
        poll_multi_threads(self.inner.shared.clone(), num_threads, callback, no_packet_callback)
    }

    /// Opens a divert object for file monitoring and interception.
    pub fn open_file(config: &crate::types::FileModuleConfig) -> anyhow::Result<Self> {
        Divert::open_file_with_driver_path(
            DEFAULT_DRIVER_NAME,
            DEFAULT_DRIVER_PATH,
            config,
        )
    }

    /// Opens a divert object for file monitoring with a specific driver path.
    pub fn open_file_with_driver_path(
        driver_name: &str,
        driver_path: &str,
        config: &crate::types::FileModuleConfig,
    ) -> anyhow::Result<Self> {
        let full_path = crate::raw::resolve_driver_path(driver_path)?;
        let handle = crate::driver_install::open_or_install_driver(driver_name, &full_path, false)
            .with_context(|| format!("Failed to open or install driver: {}", driver_name))?;

        crate::ioctl::initialize(handle, crate::types::Layer::File as u32, 0, 0)
            .context("Failed to initialize File Divert")?;
        crate::ioctl::startup_file(handle, config).context("Failed to startup File Divert")?;

        let rb_client = RingBufferClient::new(handle).context("Failed to initialize RingBuffer client")?;

        Ok(Self {
            inner: Arc::new(DivertInner {
                shared: crate::raw::SharedState::new(handle, rb_client),
            }),
        })
    }

    /// Sends a file synchronous block decision back to the driver.
    pub fn send_file_decision(&self, decision: &crate::types::FileDecision) -> anyhow::Result<()> {
        let mut bytes_returned = 0u32;
        unsafe {
            windows::Win32::System::IO::DeviceIoControl(
                self.inner.shared.handle(),
                crate::ioctl_code::IOCTL_SEND,
                Some(decision as *const _ as *const std::ffi::c_void),
                std::mem::size_of::<crate::types::FileDecision>() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        }
        .ok()
        .context("IOCTL_SEND for FileDecision failed")
    }

    /// Fetches the next available file event from the ring buffer.
    pub fn next_file_event(&self) -> Option<crate::ringbuffer::FileEventRef<'_>> {
        self.inner.shared.rb_client().next_file_event()
    }

    /// Polls for file events, invokes the callback for each one, and automatically handles synchronous decisions.
    pub fn poll_file_events<F, N>(&self, mut callback: F, mut no_event_callback: N) -> anyhow::Result<()>
    where
        F: FnMut(crate::ringbuffer::FileEventRef<'_>) -> crate::types::FileCallbackDecision,
        N: FnMut(),
    {
        loop {
            if let Some(event) = self.next_file_event() {
                let tx_id = event.event.transaction_id;
                let core_id = event.core_id;
                let old_head = event.old_head;
                let mut raw_event = event.event;

                let decision = callback(event);

                match decision {
                    crate::types::FileCallbackDecision::Allow => {
                        // Keep the ring buffer's default Allow value unchanged
                    }
                    crate::types::FileCallbackDecision::Deny => {
                        raw_event.decision = crate::types::FILE_ACTION_DENY;
                        raw_event.redirect_path_len = 0;
                        const RECORD_HEADER_SIZE: usize = 8;
                        self.inner.shared.rb_client().write_to_rb(
                            core_id,
                            old_head,
                            RECORD_HEADER_SIZE,
                            &raw_event,
                        );
                    }
                    crate::types::FileCallbackDecision::Redirect(ref path) => {
                        raw_event.decision = 3; // Redirect
                        let utf16: Vec<u16> = path.encode_utf16().collect();
                        let len = std::cmp::min(utf16.len(), crate::types::MAX_RULE_PATH_LEN);
                        raw_event.redirect_path_len = len as u32;
                        raw_event.redirect_path = [0u16; crate::types::MAX_RULE_PATH_LEN];
                        raw_event.redirect_path[..len].copy_from_slice(&utf16[..len]);
                        const RECORD_HEADER_SIZE: usize = 8;
                        self.inner.shared.rb_client().write_to_rb(
                            core_id,
                            old_head,
                            RECORD_HEADER_SIZE,
                            &raw_event,
                        );
                    }
                }

                let response = crate::types::FileDecision {
                    transaction_id: tx_id,
                };

                if let Err(err) = self.send_file_decision(&response) {
                    eprintln!("  \x1B[1;31m[-] Failed to automatically send decision: {}\x1B[0m", err);
                }
                continue;
            }

            no_event_callback();
        }
    }

    /// Helper to get a closure that waits/blocks using IOCTL when no events/packets are available.
    pub fn default_wait(&self) -> impl Fn() + Send + Sync + Clone + 'static {
        let divert = self.clone();
        move || {
            let _ = divert.wait_for_data();
        }
    }

    /// Helper to get a closure that busy polls (yields execution) when no events/packets are available.
    pub fn busy_poll(&self) -> impl Fn() + Send + Sync + Clone + 'static {
        || {
            std::thread::yield_now();
        }
    }
}

/// Helper function to create a wait closure for polling.
#[allow(non_snake_case)]
pub fn DefaultWait(divert: &Divert) -> impl Fn() + Send + Sync + Clone + 'static {
    divert.default_wait()
}

/// Helper function to create a busy-poll closure for polling.
#[allow(non_snake_case)]
pub fn BusyPoll() -> impl Fn() + Send + Sync + Clone + 'static {
    || {
        std::thread::yield_now();
    }
}
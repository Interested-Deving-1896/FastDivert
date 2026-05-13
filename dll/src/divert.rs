/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::driver_install::uninstall_driver;
use crate::ioctl_code::DivertIoctlMMapRequest;
use crate::raw::{
    open_handle, poll_cores, poll_multi_threads, recv, recv_ref, recv_ref_for_core, send,
    wait_for_data, SharedState,
};
use crate::{
    DivertAddress, PacketRef, PollMode, RingBufferClient, DEFAULT_DRIVER_NAME, DEFAULT_DRIVER_PATH,
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

    /// Polls for packets in the current thread and invokes the callback for each one.
    /// Returns an error if the driver connection is lost.
    pub fn poll<F, N>(&self, mode: PollMode, mut callback: F, mut no_packet_callback: N) -> anyhow::Result<()>
    where
        F: FnMut(PacketRef<'_>),
        N: FnMut(),
    {
        loop {
            if recv_ref(self.inner.shared.rb_client(), &mut callback) {
                continue;
            }

            match mode {
                PollMode::BusyPoll => {
                    no_packet_callback();
                }
                PollMode::Default | PollMode::IoctlWait => {
                    wait_for_data(self.inner.shared.handle())?
                }
            }
        }
    }

    /// Polls for packets continuously for specific cores in the current thread.
    /// This can be used in user-managed threads to poll for specific cores.
    pub fn poll_cores<F, N>(&self, cores: &[u32], mode: PollMode, callback: F, no_packet_callback: N) -> anyhow::Result<()>
    where
        F: FnMut(PacketRef<'_>),
        N: FnMut(),
    {
        poll_cores(self.inner.shared.clone(), cores, mode, callback, no_packet_callback)
    }

    /// Spawns multiple threads to poll for packets. Each thread monitors a subset of CPU cores.
    /// Returns the JoinHandles for the spawned threads.
    pub fn poll_multi_threads<F, N>(
        &self,
        num_threads: u32,
        mode: PollMode,
        callback: F,
        no_packet_callback: N,
    ) -> Vec<thread::JoinHandle<()>>
    where
        F: Fn(u32, PacketRef<'_>) + Send + Sync + Clone + 'static,
        N: FnMut() + Send + Sync + Clone + 'static,
    {
        poll_multi_threads(self.inner.shared.clone(), num_threads, mode, callback, no_packet_callback)
    }
}

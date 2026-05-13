/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::driver_install::open_or_install_driver;
use crate::ioctl::{initialize, startup};
use crate::{ioctl_code, DivertAddress, PacketData, PacketRef, PollMode, RingBufferClient};
use anyhow::{bail, Context};
use std::thread;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;

/// A thread-safe wrapper around a Windows HANDLE and RingBufferClient.
struct SharedStateInner {
    handle: HANDLE,
    rb_client: RingBufferClient,
}

// Windows HANDLE (void pointer) is not Send/Sync by default in the `windows` crate,
// but it is safe to share handles across threads for overlapping IO or DeviceIoControl.
unsafe impl Send for SharedStateInner {}
unsafe impl Sync for SharedStateInner {}

/// Thread-safe reference-counted state for use with raw polling functions.
#[derive(Clone)]
pub struct SharedState {
    inner: std::sync::Arc<SharedStateInner>,
}

impl SharedState {
    pub fn new(handle: HANDLE, rb_client: RingBufferClient) -> Self {
        Self {
            inner: std::sync::Arc::new(SharedStateInner { handle, rb_client }),
        }
    }

    pub fn handle(&self) -> HANDLE {
        self.inner.handle
    }

    pub fn rb_client(&self) -> &RingBufferClient {
        &self.inner.rb_client
    }
}

/// Internal helper to check the filter string.
fn check_filter(filter: &str) -> anyhow::Result<()> {
    if filter != "true" {
        bail!("Filter expressions other than 'true' are not yet supported");
    }
    Ok(())
}

/// Internal helper to resolve driver path. If only a filename is provided,
/// it resolves to the current executable's directory.
fn resolve_driver_path(path: &str) -> anyhow::Result<String> {
    let p = std::path::Path::new(path);
    if p.components().count() <= 1 {
        let mut driver_path = std::env::current_exe()
            .context("Failed to get current executable path")?
            .parent()
            .context("Failed to get executable directory")?
            .to_path_buf();
        driver_path.push(path);
        Ok(driver_path.to_string_lossy().into_owned())
    } else {
        Ok(path.to_string())
    }
}

/// Opens a handle to the driver with a specific path.
pub fn open_handle(
    filter: &str,
    driver_name: &str,
    driver_path: &str,
    layer: u32,
    priority: u32,
    flags: u64,
) -> anyhow::Result<HANDLE> {
    check_filter(filter)?;
    let full_path = resolve_driver_path(driver_path)?;
    let handle = open_or_install_driver(driver_name, &full_path, false)
        .with_context(|| format!("Failed to open or install driver: {}", driver_name))?;

    initialize(handle, layer, priority, flags).with_context(|| {
        format!(
            "Failed to initialize Divert (layer: {}, priority: {})",
            layer, priority
        )
    })?;
    startup(handle).context("Failed to start Divert driver instance")?;

    Ok(handle)
}

/// Sends a packet via a raw driver handle.
pub fn send(rb_client: &RingBufferClient, addr: &DivertAddress, data: &[u8]) -> anyhow::Result<()> {
    rb_client
        .push_send_packet(addr, data)
        .with_context(|| "RingBuffer push failed: the buffer might be full")?;
    rb_client.flush_send()?;
    Ok(())
}

/// Receives a packet via a raw driver handle into a buffer.
pub fn recv(rb_client: &RingBufferClient, buffer: &mut [u8]) -> anyhow::Result<Option<usize>> {
    if let Some(packet_ref) = rb_client.next_packet() {
        let len = packet_ref.data.len();
        if len <= buffer.len() {
            match &packet_ref.data {
                PacketData::Contiguous(s) => {
                    buffer[..len].copy_from_slice(s);
                }
                PacketData::Wrapped { part1, part2 } => {
                    let l1 = part1.len();
                    buffer[..l1].copy_from_slice(part1);
                    buffer[l1..len].copy_from_slice(part2);
                }
            }
            Ok(Some(len))
        } else {
            bail!(
                "Provided buffer size ({}) is smaller than packet size ({})",
                buffer.len(),
                len
            )
        }
    } else {
        Ok(None)
    }
}

/// Receives a packet via a raw driver handle and provides a reference.
pub fn recv_ref<F>(rb_client: &RingBufferClient, callback: F) -> bool
where
    F: FnOnce(PacketRef<'_>),
{
    if let Some(packet_ref) = rb_client.next_packet() {
        callback(packet_ref);
        true
    } else {
        false
    }
}

/// Receives a packet from a specific core via a raw driver handle and provides a reference.
pub fn recv_ref_for_core<F>(rb_client: &RingBufferClient, core: u32, callback: F) -> bool
where
    F: FnOnce(PacketRef<'_>),
{
    if let Some(packet_ref) = rb_client.next_packet_for_core(core) {
        callback(packet_ref);
        true
    } else {
        false
    }
}

/// Blocks until the driver indicates that new packet data is available in the ring buffer.
pub fn wait_for_data(handle: HANDLE) -> anyhow::Result<()> {
    let mut bytes_returned = 0u32;
    unsafe {
        DeviceIoControl(
            handle,
            ioctl_code::IOCTL_RECV,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    }
    .ok()
    .context("IOCTL_RECV failed: driver handle might be closed or invalid")
}

/// Polls for packets continuously for specific cores given a ringbuffer client and handle.
/// This allows the user to manage their own threads and just call this function.
pub fn poll_cores<F, N>(
    shared_state: SharedState,
    cores: &[u32],
    mode: PollMode,
    mut callback: F,
    mut no_packet_callback: N,
) -> anyhow::Result<()>
where
    F: FnMut(PacketRef<'_>),
    N: FnMut(),
{
    let handle = shared_state.handle();
    let rb_client = shared_state.rb_client();

    loop {
        let mut processed = false;
        for &core in cores {
            if let Some(packet) = rb_client.next_packet_for_core(core) {
                callback(packet);
                processed = true;
                break;
            }
        }

        if !processed {
            match mode {
                PollMode::BusyPoll => {
                    no_packet_callback();
                }
                PollMode::Default | PollMode::IoctlWait => {
                    wait_for_data(handle)?;
                }
            }
        }
    }
}

/// Spawns multiple threads to poll for packets given a ringbuffer client and handle.
pub fn poll_multi_threads<F, N>(
    shared_state: SharedState,
    num_threads: u32,
    mode: PollMode,
    callback: F,
    no_packet_callback: N,
) -> Vec<thread::JoinHandle<()>>
where
    F: Fn(u32, PacketRef<'_>) + Send + Sync + Clone + 'static,
    N: FnMut() + Send + Sync + Clone + 'static,
{
    let mut handles = Vec::with_capacity(num_threads.max(1) as usize);
    let max_cores = shared_state.rb_client().max_cores();

    let actual_threads = num_threads.min(max_cores).max(1);

    for thread_idx in 0..actual_threads {
        let state = shared_state.clone();
        let cb = callback.clone();
        let ncb = no_packet_callback.clone();

        let cores: Vec<u32> = (thread_idx..max_cores)
            .step_by(actual_threads as usize)
            .collect();

        handles.push(thread::spawn(move || {
            let _ = poll_cores(state, &cores, mode, |p| cb(thread_idx, p), ncb);
        }));
    }
    handles
}

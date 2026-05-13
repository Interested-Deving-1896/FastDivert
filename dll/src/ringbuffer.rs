/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use crate::ioctl::map_rb;
use crate::ioctl_code::{DivertIoctlMMapRequest, IOCTL_RECV, IOCTL_SEND};
use crate::DivertAddress;
use anyhow::{anyhow, Context, Result};
use std::mem::size_of;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use windows::Win32::Foundation::*;
use windows::Win32::System::IO::DeviceIoControl;
// Data structures matching the kernel-side ring buffer layout.

/// Each entry in the ring buffer starts with a RecordHeader.
///
/// The Divert protocol uses a "Two-Record" sequence for every packet:
/// 1. An **Address Record**: Header (ty=0) + DivertAddress struct.
/// 2. A **Packet Record**: Header (ty=1) + Raw packet bytes.
///
/// This allows the driver to pass complex metadata alongside the raw capture.
#[repr(C)]
#[derive(Copy, Clone)]
struct RecordHeader {
    len: u32,
    ty: u32,
}

#[repr(C, align(64))]
struct ConsumerHeader {
    head: AtomicUsize,
}

#[repr(C, align(64))]
struct ProducerHeader {
    tail: AtomicUsize,
}

#[repr(C, align(64))]
struct RingBufferHeader {
    p: ProducerHeader,
    c: ConsumerHeader,
}

/// Represents a view into a packet's data within the ring buffer.
/// This can be a single contiguous slice or two slices if the data wraps around the buffer's end.
pub enum PacketData<'a> {
    Contiguous(&'a [u8]),
    Wrapped { part1: &'a [u8], part2: &'a [u8] },
}

impl<'a> PacketData<'a> {
    pub fn len(&self) -> usize {
        match self {
            PacketData::Contiguous(s) => s.len(),
            PacketData::Wrapped { part1, part2 } => part1.len() + part2.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the packet data into a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.len());
        match self {
            PacketData::Contiguous(s) => vec.extend_from_slice(s),
            PacketData::Wrapped { part1, part2 } => {
                vec.extend_from_slice(part1);
                vec.extend_from_slice(part2);
            }
        }
        vec
    }
}

/// A reference to a packet in the ring buffer.
/// The ring buffer's read pointer (`head`) is advanced only when this reference is dropped.
/// This ensures the data is valid as long as this reference exists.
pub struct PacketRef<'a> {
    pub core_id: u32,
    pub record_type: u32,
    pub address: DivertAddress,
    pub data: PacketData<'a>,

    // Internals for advancing the ring buffer head on drop
    header_ptr: *mut RingBufferHeader,
    old_head: usize,
    record_len: usize,
}

impl<'a> Drop for PacketRef<'a> {
    fn drop(&mut self) {
        // Advance the head pointer to release the buffer space.
        let new_head = self.old_head.wrapping_add(self.record_len);
        unsafe {
            (*self.header_ptr).c.head.store(new_head, Ordering::Release);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Defines the strategy for polling for packets.
pub enum PollMode {
    /// `Default`: `IoctlWait` mode
    Default,
    /// `BusyPoll`: Intended for use in a loop. If no packet is ready, a user-provided
    /// callback is invoked before trying one more time.
    BusyPoll,
    /// `IoctlWait`: If no packet is ready, block and wait for a signal from the driver.
    IoctlWait,
}

/// A client for the kernel-mode ring buffer.
/// It provides methods to read packets from the shared memory region.
pub struct RingBufferClient {
    handle: HANDLE,
    max_cores: u32,
    headers: *mut RingBufferHeader,
    data_addrs: *mut u8,
    send_headers: *mut RingBufferHeader,
    send_data_addrs: *mut u8,
    size: usize,
    mask: usize, // size - 1

    // State for iterating over cores
    current_core: AtomicU32,
}

// Safety: RingBufferClient manages access to shared memory using atomic operations
// and pointers that are valid for its lifetime.
unsafe impl Send for RingBufferClient {}
unsafe impl Sync for RingBufferClient {}

impl RingBufferClient {
    pub fn new(handle: HANDLE) -> Result<Self> {
        Self::new_with_config(handle, DivertIoctlMMapRequest { max_cores: 0 })
    }

    pub fn new_with_config(handle: HANDLE, req: DivertIoctlMMapRequest) -> Result<Self> {
        let map_result = map_rb(handle, req).context("Failed to map ring buffer memory")?;

        let size = map_result.rb_size as usize;
        if size == 0 || (size & (size - 1)) != 0 {
            return Err(anyhow!(
                "Ring buffer size must be a power of 2, got: {}",
                size
            ));
        }

        Ok(Self {
            handle,
            max_cores: map_result.max_cores,
            headers: map_result.ring_buffer_header as *mut RingBufferHeader,
            data_addrs: map_result.ring_buffer_data,
            send_headers: map_result.send_ring_buffer_header as *mut RingBufferHeader,
            send_data_addrs: map_result.send_ring_buffer_data,
            size,
            mask: size - 1,
            current_core: AtomicU32::new(0),
        })
    }

    pub fn max_cores(&self) -> u32 {
        self.max_cores
    }

    /// Fetches the next available packet from any of the core-specific ring buffers.
    /// It round-robins through the cores.
    pub fn next_packet(&self) -> Option<PacketRef<'_>> {
        for _ in 0..self.max_cores {
            let core = self.current_core.fetch_add(1, Ordering::Relaxed) % self.max_cores;
            if let Some(packet) = self.next_packet_for_core(core) {
                return Some(packet);
            }
        }
        None
    }

    /// Fetches the next available packet from a specific core's ring buffer.
    /// This is the core logic for reading packets from the shared memory.
    pub fn next_packet_for_core(&self, core: u32) -> Option<PacketRef<'_>> {
        if core >= self.max_cores {
            return None;
        }

        let header_ptr = unsafe { self.headers.add(core as usize) };
        let buffer_data = unsafe { self.data_addrs.add(core as usize * self.size) };

        // Load current buffer indices
        let (head, _, unread_size) = self.get_buffer_status(header_ptr);

        const RECORD_HEADER_SIZE: usize = size_of::<RecordHeader>();
        const ADDRESS_SIZE: usize = size_of::<DivertAddress>();

        // --- Phase 1: Check for Address Record ---
        if unread_size == 0 || unread_size > self.size {
            return None;
        }

        if unread_size < RECORD_HEADER_SIZE + ADDRESS_SIZE {
            return None;
        }

        // Read the header of the first record (The Address Record)
        let rh1_offset = head & self.mask;
        let rh1 = self.read_from_rb::<RecordHeader>(buffer_data, rh1_offset);

        // Consistency check: Ensure the first record is exactly the size of a DivertAddress.
        if rh1.len as usize != ADDRESS_SIZE {
            // If length mismatch, the ring buffer protocol is out of sync.
            // Returning None here prevents processing garbage data.
            return None;
        }

        // Extract the DivertAddress metadata
        let addr_offset = (head + RECORD_HEADER_SIZE) & self.mask;
        let address = self.read_from_rb::<DivertAddress>(buffer_data, addr_offset);

        // --- Phase 2: Check for Packet Record ---
        let rh2_absolute_pos = head + RECORD_HEADER_SIZE + ADDRESS_SIZE;
        let total_so_far = RECORD_HEADER_SIZE + ADDRESS_SIZE;

        // Ensure the second header (Packet Header) has been written by the producer.
        if unread_size < total_so_far + RECORD_HEADER_SIZE {
            return None;
        }

        // Read the header of the second record (The Packet Data Record)
        let rh2_offset = rh2_absolute_pos & self.mask;
        let rh2 = self.read_from_rb::<RecordHeader>(buffer_data, rh2_offset);

        let data_len = rh2.len as usize;
        let total_record_len = total_so_far + RECORD_HEADER_SIZE + data_len;

        // Ensure the producer has finished writing the full payload.
        if unread_size < total_record_len {
            return None;
        }

        let data_offset = (rh2_absolute_pos + RECORD_HEADER_SIZE) & self.mask;
        let packet_data = self.get_packet_data_view(buffer_data, data_offset, data_len);

        Some(PacketRef {
            core_id: core,
            record_type: rh2.ty,
            address,
            data: packet_data,
            header_ptr,
            old_head: head,
            record_len: total_record_len, // Advance past both records on drop.
        })
    }

    /// Helper: Read a Sized type from the ring buffer, handling wrap-around.
    fn read_from_rb<T: Copy>(&self, buffer: *const u8, offset: usize) -> T {
        let size = size_of::<T>();
        if offset + size <= self.size {
            unsafe { std::ptr::read_unaligned(buffer.add(offset) as *const T) }
        } else {
            let mut temp = std::mem::MaybeUninit::<T>::uninit();
            self.copy_data_from_rb(buffer, offset, unsafe {
                std::slice::from_raw_parts_mut(temp.as_mut_ptr() as *mut u8, size)
            });
            unsafe { temp.assume_init() }
        }
    }

    /// Internal helper: Atomically load buffer pointer state.
    fn get_buffer_status(&self, header_ptr: *mut RingBufferHeader) -> (usize, usize, usize) {
        let head = unsafe { (*header_ptr).c.head.load(Ordering::Acquire) };
        let tail = unsafe { (*header_ptr).p.tail.load(Ordering::Acquire) };
        let unread_size = tail.wrapping_sub(head);
        (head, tail, unread_size)
    }

    /// Returns a view of a slice of the ring buffer, handling wrap-around.
    fn get_packet_data_view<'a>(
        &self,
        buffer: *const u8,
        offset: usize,
        len: usize,
    ) -> PacketData<'a> {
        let len1 = (self.size - offset).min(len);
        let len2 = len - len1;

        unsafe {
            if len2 == 0 {
                PacketData::Contiguous(std::slice::from_raw_parts(buffer.add(offset), len))
            } else {
                PacketData::Wrapped {
                    part1: std::slice::from_raw_parts(buffer.add(offset), len1),
                    part2: std::slice::from_raw_parts(buffer, len2),
                }
            }
        }
    }

    /// Copies data from the ring buffer to a destination slice, handling wrap-around.
    fn copy_data_from_rb(&self, buffer: *const u8, offset: usize, dest: &mut [u8]) {
        let len = dest.len();
        let len1 = (self.size - offset).min(len);
        let len2 = len - len1;

        unsafe {
            let dest_ptr = dest.as_mut_ptr();
            std::ptr::copy_nonoverlapping(buffer.add(offset), dest_ptr, len1);
            if len2 > 0 {
                std::ptr::copy_nonoverlapping(buffer, dest_ptr.add(len1), len2);
            }
        }
    }

    pub fn push_send_packet(&self, addr: &DivertAddress, data: &[u8]) -> Result<()> {
        let core = 0; // Default to core 0 for send ringbuffer
        let send_header_ptr = unsafe { self.send_headers.add(core) };
        let send_data_buffer = self.send_data_addrs; // since core is 0

        let (head, tail, unread_size) = self.get_buffer_status(send_header_ptr);

        // Defensive check to avoid underflow if the ring buffer state is corrupted.
        if unread_size > self.size || tail < head.wrapping_sub(self.size) {
            return Err(anyhow!("Send ring buffer state corruption detected"));
        }
        let free_space = self.size.saturating_sub(unread_size);

        const RH_SIZE: usize = size_of::<RecordHeader>();
        const ADDR_SIZE: usize = size_of::<DivertAddress>();

        // Packet structure: (RecordHeader + Address) + (RecordHeader + Payload)
        let total_required_size = (RH_SIZE * 2) + ADDR_SIZE + data.len();

        if free_space < total_required_size {
            return Err(anyhow!(
                "Send ring buffer is full (required: {}, free: {})",
                total_required_size,
                free_space
            ));
        }

        // --- Step 1: Write the Address Record ---
        let addr_header = RecordHeader {
            len: ADDR_SIZE as u32,
            ty: 0, // Type 0: Address metadata
        };
        let mut current_offset = tail & self.mask;

        self.copy_to_buffer(
            send_data_buffer,
            &mut current_offset,
            as_u8_slice(&addr_header),
        );
        self.copy_to_buffer(send_data_buffer, &mut current_offset, as_u8_slice(addr));

        // --- Step 2: Write the Packet Data Record ---
        let packet_header = RecordHeader {
            len: data.len() as u32,
            ty: 1, // Type 1: Packet payload
        };

        self.copy_to_buffer(
            send_data_buffer,
            &mut current_offset,
            as_u8_slice(&packet_header),
        );
        self.push_data_to_rb(send_data_buffer, current_offset, data);

        // 3. Atomically update Tail to notify the driver.
        unsafe {
            (*send_header_ptr)
                .p
                .tail
                .store(tail.wrapping_add(total_required_size), Ordering::Release);
        }
        Ok(())
    }

    /// Helper: Write data to the buffer and update the provided offset (handles masking).
    fn copy_to_buffer(&self, buffer: *mut u8, offset: &mut usize, src: &[u8]) {
        self.push_data_to_rb(buffer, *offset, src);
        *offset = (*offset + src.len()) & self.mask;
    }

    fn push_data_to_rb(&self, buffer: *mut u8, offset: usize, src: &[u8]) {
        let len = src.len();
        let len1 = (self.size - offset).min(len);
        let len2 = len - len1;

        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), buffer.add(offset), len1);
            if len2 > 0 {
                std::ptr::copy_nonoverlapping(src.as_ptr().add(len1), buffer, len2);
            }
        }
    }

    pub fn flush_send(&self) -> Result<()> {
        let mut bytes_returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_SEND,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        }
        .ok()
        .context("Failed to flush send buffer via IOCTL_SEND")
    }

    pub fn wait_for_data(&self) -> Result<()> {
        let mut bytes_returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_RECV,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        }
        .ok()
        .context("Failed to wait for data via IOCTL_RECV")
    }

    /// Polls for a packet using the specified mode.
    ///
    /// This method provides a unified interface for different polling strategies.
    ///
    /// # Arguments
    ///
    /// * `mode`: The `PollMode` to use.
    ///   - `PollMode::Default`: `PollMode::IoctlWait` mode.
    ///   - `PollMode::BusyPoll`: If no packet is available, invokes the `on_no_packet`
    ///     callback, then tries to receive a packet again. This is intended for
    ///     use in a polling loop.
    ///   - `PollMode::IoctlWait`: If no packet is available, it blocks and waits for the
    ///     driver to signal that data is ready, then tries to receive again.
    /// * `on_no_packet`: A closure called when `mode` is `PollMode::BusyPoll`
    ///   and no packet is immediately available. For other modes, this closure is ignored.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<PacketRef>`.
    /// `Ok(Some(packet))` if a packet was found.
    /// `Ok(None)` if no packet was found after applying the polling strategy.
    /// `Err` if an error occurred (e.g., during `IoctlWait`).
    pub fn poll<'a, F>(&'a self, mode: PollMode, mut on_no_packet: F) -> Result<Option<PacketRef<'a>>>
    where
        F: FnMut(),
    {
        // First attempt to get a packet, common to all modes.
        if let Some(packet) = self.next_packet() {
            return Ok(Some(packet));
        }

        // If no packet was found, apply the strategy determined by the poll mode.
        match mode {
            PollMode::BusyPoll => {
                // In busy-poll mode, invoke the provided callback.
                on_no_packet();
                // After the callback, try one more time to get a packet.
                Ok(self.next_packet())
            }
            PollMode::Default |PollMode::IoctlWait => {
                // In wait mode, block until the driver signals data is available.
                self.wait_for_data()?;
                // After waiting, try one more time to get a packet.
                Ok(self.next_packet())
            }
        }
    }
}

/// Helper to view any Sized type as a u8 slice for memory copying.
fn as_u8_slice<T: Sized>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, size_of::<T>()) }
}

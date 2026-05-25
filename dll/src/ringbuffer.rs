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
#[derive(Clone, Copy, Debug)]
struct RecordHeader {
    len: u32,
    _reserved: u32,
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

/// A reference to a file event in the ring buffer.
/// The ring buffer's read pointer (`head`) is advanced only when this reference is dropped.
/// This ensures the data is valid as long as this reference exists.
pub struct FileEventRef<'a> {
    pub core_id: u32,
    pub event: crate::types::FileEvent,
    pub path: String,

    // Internals for advancing the ring buffer head on drop
    header_ptr: *mut RingBufferHeader,
    pub(crate) old_head: usize,
    record_len: usize,
    rb_client: &'a RingBufferClient,
}

impl<'a> Drop for FileEventRef<'a> {
    fn drop(&mut self) {
        // Advance the head pointer to release the buffer space.
        let new_head = self.old_head.wrapping_add(self.record_len);
        unsafe {
            (*self.header_ptr).c.head.store(new_head, Ordering::Release);
        }
    }
}

impl<'a> FileEventRef<'a> {
    pub fn set_decision(&self, decision: crate::types::FileCallbackDecision) {
        let mut event = self.event;
        match decision {
            crate::types::FileCallbackDecision::Allow => {
                event.decision = crate::types::FILE_ACTION_ALLOW;
                event.redirect_path_len = 0;
            }
            crate::types::FileCallbackDecision::Deny => {
                event.decision = crate::types::FILE_ACTION_DENY;
                event.redirect_path_len = 0;
            }
            crate::types::FileCallbackDecision::Redirect(ref target_path) => {
                event.decision = 3; // Redirect
                let utf16: Vec<u16> = target_path.encode_utf16().collect();
                let len = utf16.len().min(crate::types::MAX_RULE_PATH_LEN);
                event.redirect_path_len = len as u32;
                event.redirect_path = [0u16; crate::types::MAX_RULE_PATH_LEN];
                event.redirect_path[..len].copy_from_slice(&utf16[..len]);
            }
        }

        // Overwrite the FileEvent structure inside the ring buffer.
        // It resides at old_head + RECORD_HEADER_SIZE.
        const RECORD_HEADER_SIZE: usize = size_of::<RecordHeader>();
        self.rb_client.write_to_rb(
            self.core_id,
            self.old_head,
            RECORD_HEADER_SIZE,
            &event,
        );
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

    pub fn handle(&self) -> HANDLE {
        self.handle
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

        const RECORD_HEADER_SIZE: usize = size_of::<RecordHeader>();
        const ADDRESS_SIZE: usize = size_of::<DivertAddress>();

        loop {
            // Load current buffer indices
            let (head, _, unread_size) = self.get_buffer_status(header_ptr);

            if unread_size == 0 || unread_size > self.size {
                return None;
            }

            if unread_size < RECORD_HEADER_SIZE {
                return None;
            }

            // Read the single RecordHeader
            let rh_offset = head & self.mask;
            let rh = self.read_from_rb::<RecordHeader>(buffer_data, rh_offset);

            // Check if it's a dummy record (failed transaction in CAS MPSC mode)
            if rh._reserved == 0xDEADBEEF {
                let total_record_len = RECORD_HEADER_SIZE + rh.len as usize;
                if unread_size < total_record_len {
                    return None; // Wait until the dummy record is fully committed
                }
                // Skip the dummy record by advancing the head
                let new_head = head.wrapping_add(total_record_len);
                unsafe {
                    (*header_ptr).c.head.store(new_head, Ordering::Release);
                }
                continue; // Process next record
            }

            if unread_size < RECORD_HEADER_SIZE + ADDRESS_SIZE {
                return None;
            }

            // Consistency check: Ensure the length contains at least the DivertAddress
            if (rh.len as usize) < ADDRESS_SIZE {
                return None;
            }

            let total_record_len = RECORD_HEADER_SIZE + rh.len as usize;

            // Ensure the producer has finished writing the full record (header + address + payload)
            if unread_size < total_record_len {
                return None;
            }

            // Extract the DivertAddress metadata
            let addr_offset = (head + RECORD_HEADER_SIZE) & self.mask;
            let address = self.read_from_rb::<DivertAddress>(buffer_data, addr_offset);

            // Construct PacketData view of the payload bytes starting after DivertAddress
            let data_len = rh.len as usize - ADDRESS_SIZE;
            let data_offset = (head + RECORD_HEADER_SIZE + ADDRESS_SIZE) & self.mask;
            let packet_data = self.get_packet_data_view(buffer_data, data_offset, data_len);

            return Some(PacketRef {
                core_id: core,
                record_type: 0, // This is reserved / unused now
                address,
                data: packet_data,
                header_ptr,
                old_head: head,
                record_len: total_record_len, // Advance past the single unified record on drop
            });
        }
    }

    /// Fetches the next available file event from any of the core-specific ring buffers.
    /// It round-robins through the cores.
    pub fn next_file_event(&self) -> Option<FileEventRef<'_>> {
        for _ in 0..self.max_cores {
            let core = self.current_core.fetch_add(1, Ordering::Relaxed) % self.max_cores;
            if let Some(event) = self.next_file_event_for_core(core) {
                return Some(event);
            }
        }
        None
    }

    /// Fetches the next available file event from a specific core's ring buffer.
    pub fn next_file_event_for_core(&self, core: u32) -> Option<FileEventRef<'_>> {
        if core >= self.max_cores {
            return None;
        }

        let header_ptr = unsafe { self.headers.add(core as usize) };
        let buffer_data = unsafe { self.data_addrs.add(core as usize * self.size) };

        const RECORD_HEADER_SIZE: usize = size_of::<RecordHeader>();
        let file_event_size: usize = size_of::<crate::types::FileEvent>();

        loop {
            // Load current buffer indices
            let (head, _, unread_size) = self.get_buffer_status(header_ptr);

            if unread_size == 0 || unread_size > self.size {
                return None;
            }

            if unread_size < RECORD_HEADER_SIZE {
                return None;
            }

            // Read the record header
            let rh_offset = head & self.mask;
            let rh = self.read_from_rb::<RecordHeader>(buffer_data, rh_offset);

            // Check if it's a dummy record (failed transaction in CAS MPSC mode)
            if rh._reserved == 0xDEADBEEF {
                let total_record_len = RECORD_HEADER_SIZE + rh.len as usize;
                if unread_size < total_record_len {
                    return None; // Wait until the dummy record is fully committed
                }
                // Skip the dummy record by advancing the head
                let new_head = head.wrapping_add(total_record_len);
                unsafe {
                    (*header_ptr).c.head.store(new_head, Ordering::Release);
                }
                continue; // Process next record
            }

            if unread_size < RECORD_HEADER_SIZE + file_event_size {
                return None;
            }

            let record_len = rh.len as usize; // size_of::<FileEvent>() + path_len * 2
            let total_record_len = RECORD_HEADER_SIZE + record_len;

            // Ensure the entire record is written in the ring buffer
            if unread_size < total_record_len {
                return None;
            }

            // Read the FileEvent struct
            let event_offset = (head + RECORD_HEADER_SIZE) & self.mask;
            let event = self.read_from_rb::<crate::types::FileEvent>(buffer_data, event_offset);

            // Read the path
            let path_u16_len = event.path_len as usize;
            let mut path_u16 = vec![0u16; path_u16_len];
            if path_u16_len > 0 {
                let path_offset = (head + RECORD_HEADER_SIZE + file_event_size) & self.mask;
                self.copy_data_from_rb(buffer_data, path_offset, unsafe {
                    std::slice::from_raw_parts_mut(path_u16.as_mut_ptr() as *mut u8, path_u16_len * 2)
                });
            }
            let path = String::from_utf16_lossy(&path_u16);

            return Some(FileEventRef {
                core_id: core,
                event,
                path,
                header_ptr,
                old_head: head,
                record_len: total_record_len,
                rb_client: self,
            });
        }
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

    /// Overwrites a Sized type inside the ring buffer, handling wrap-around.
    pub fn write_to_rb<T: Sized>(&self, core: u32, start_tail: usize, offset_from_start: usize, value: &T) {
        let size = size_of::<T>();
        let buffer_data = unsafe { self.data_addrs.add(core as usize * self.size) };
        let write_offset = (start_tail + offset_from_start) & self.mask;
        let len1 = (self.size - write_offset).min(size);
        let len2 = size - len1;

        unsafe {
            std::ptr::copy_nonoverlapping(value as *const T as *const u8, buffer_data.add(write_offset), len1);
            if len2 > 0 {
                std::ptr::copy_nonoverlapping((value as *const T as *const u8).add(len1), buffer_data, len2);
            }
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

        // Unified layout: RecordHeader + DivertAddress + PacketData
        let total_required_size = RH_SIZE + ADDR_SIZE + data.len();

        if free_space < total_required_size {
            return Err(anyhow!(
                "Send ring buffer is full (required: {}, free: {})",
                total_required_size,
                free_space
            ));
        }

        // --- Step 1: Write the Unified RecordHeader ---
        let unified_header = RecordHeader {
            len: (ADDR_SIZE + data.len()) as u32,
            _reserved: 0,
        };
        let mut current_offset = tail & self.mask;

        self.copy_to_buffer(
            send_data_buffer,
            &mut current_offset,
            as_u8_slice(&unified_header),
        );

        // --- Step 2: Write the DivertAddress ---
        self.copy_to_buffer(send_data_buffer, &mut current_offset, as_u8_slice(addr));

        // --- Step 3: Write the Packet Data ---
        self.push_data_to_rb(send_data_buffer, current_offset, data);

        // 4. Atomically update Tail to notify the driver.
        unsafe {
            (*send_header_ptr)
                .p
                .tail
                .store(tail.wrapping_add(total_required_size), Ordering::Release);
        }
        Ok(())
    }

    pub fn push_send_packet_data(&self, addr: &DivertAddress, data: &PacketData<'_>) -> Result<()> {
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

        let data_len = data.len();
        let total_required_size = RH_SIZE + ADDR_SIZE + data_len;

        if free_space < total_required_size {
            return Err(anyhow!(
                "Send ring buffer is full (required: {}, free: {})",
                total_required_size,
                free_space
            ));
        }

        // --- Step 1: Write the Unified RecordHeader ---
        let unified_header = RecordHeader {
            len: (ADDR_SIZE + data_len) as u32,
            _reserved: 0,
        };
        let mut current_offset = tail & self.mask;

        self.copy_to_buffer(
            send_data_buffer,
            &mut current_offset,
            as_u8_slice(&unified_header),
        );

        // --- Step 2: Write the DivertAddress ---
        self.copy_to_buffer(send_data_buffer, &mut current_offset, as_u8_slice(addr));

        // --- Step 3: Write the Packet Data (handles wrapped buffers zero-copy) ---
        match data {
            PacketData::Contiguous(slice) => {
                self.push_data_to_rb(send_data_buffer, current_offset, slice);
            }
            PacketData::Wrapped { part1, part2 } => {
                let mut tmp_offset = current_offset;
                self.copy_to_buffer(send_data_buffer, &mut tmp_offset, part1);
                self.push_data_to_rb(send_data_buffer, tmp_offset, part2);
            }
        }

        // 4. Atomically update Tail to notify the driver.
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
    pub fn poll<'a, F>(&'a self, mut on_no_packet: F) -> Result<Option<PacketRef<'a>>>
    where
        F: FnMut(),
    {
        // First attempt to get a packet.
        if let Some(packet) = self.next_packet() {
            return Ok(Some(packet));
        }

        // Invoke the callback and try one more time.
        on_no_packet();
        Ok(self.next_packet())
    }
}

/// Helper to view any Sized type as a u8 slice for memory copying.
fn as_u8_slice<T: Sized>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, size_of::<T>()) }
}

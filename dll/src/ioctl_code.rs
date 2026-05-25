pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const FILE_DEVICE_NETWORK: u32 = 0x00000012;
pub const METHOD_OUT_DIRECT: u32 = 2;
pub const METHOD_IN_DIRECT: u32 = 1;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;

pub const IOCTL_INITIALIZE: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x921,
    METHOD_OUT_DIRECT,
    FILE_READ_DATA | FILE_WRITE_DATA,
);

pub const IOCTL_STARTUP: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x922,
    METHOD_IN_DIRECT,
    FILE_READ_DATA | FILE_WRITE_DATA,
);

pub const IOCTL_RECV: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x923,
    METHOD_OUT_DIRECT,
    FILE_READ_DATA,
);

pub const IOCTL_SEND: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x924,
    METHOD_IN_DIRECT,
    FILE_READ_DATA | FILE_WRITE_DATA,
);

pub const IOCTL_MAP_MM: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x930,
    METHOD_OUT_DIRECT,
    FILE_READ_DATA | FILE_WRITE_DATA,
);

pub const IOCTL_SET_BPF: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x931,
    METHOD_IN_DIRECT,
    FILE_READ_DATA | FILE_WRITE_DATA,
);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlInitialize {
    pub layer: u32,
    pub priority: u32,
    pub flags: u64,
}

/// Response structure for [DivertIoctlInitialize].
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct IoctlInitializeResponse {
    magic: u64, // Magic number (in/out).
    major: u32, // Driver major version (in/out).
    minor: u32, // Driver minor version (in/out).
    bits: u32,  // 32 or 64 (in/out).
    reserved32: [u32; 3],
    reserved64: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlStartup {
    pub flags: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlMMapRequest {
    pub max_cores: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct DivertIoctlMMapResponse {
    pub max_cores: u32,
    pub rb_size: u32,
    pub ring_buffer_header: *mut u8,
    pub ring_buffer_data: *mut u8,
    pub send_ring_buffer_header: *mut u8,
    pub send_ring_buffer_data: *mut u8,
}
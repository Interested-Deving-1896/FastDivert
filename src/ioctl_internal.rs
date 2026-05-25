/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use wdk_sys::{
    FILE_DEVICE_NETWORK, FILE_READ_DATA, FILE_WRITE_DATA, METHOD_IN_DIRECT, METHOD_OUT_DIRECT,
    PVOID,
};
use crate::network::bpf::BpfInsn;

pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_VERSION: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x920,
    METHOD_OUT_DIRECT,
    FILE_READ_DATA | FILE_WRITE_DATA,
);
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
pub const IOCTL_SET_PARAM: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x925,
    METHOD_IN_DIRECT,
    FILE_READ_DATA | FILE_WRITE_DATA,
);
pub const IOCTL_GET_PARAM: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x926,
    METHOD_OUT_DIRECT,
    FILE_READ_DATA,
);
pub const IOCTL_SHUTDOWN: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    0x927,
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

#[repr(C, packed)]
pub struct DivertVersion {
    pub magic: u64,
    pub major: u32,
    pub minor: u32,
    pub bits: u32,
    pub reserved32: [u32; 3],
    pub reserved64: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlRecv {
    pub addr: u64,
    pub addr_len_ptr: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlSend {
    pub addr: u64,
    pub addr_len: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlInitialize {
    pub layer: u32,
    pub priority: u32,
    pub flags: u64,
}

/// Response structure for [IOCTL_INITIALIZE].
#[repr(C)]
#[derive(Debug, Copy, Clone)]
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
pub struct DivertIoctlShutdown {
    pub how: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlGetParam {
    pub param: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlSetParam {
    pub val: u64,
    pub param: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertIoctlMMapRequest {
    pub max_cores: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IoctlMMapResponse {
    pub max_cores: u32,
    pub size: u32,
    pub ring_buffer_header: PVOID,
    pub ring_buffer_data: PVOID,
    pub send_ring_buffer_header: PVOID,
    pub send_ring_buffer_data: PVOID,
}

pub const MAX_FILTER_RULES: usize = 16;
pub const MAX_RULE_PATH_LEN: usize = 260; // Max Win32 path length

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileFilterRule {
    pub operation_mask: u32, // Bitmask: 1=Create, 2=Write, 4=Delete, 8=Rename
    pub match_type: u32,     // MatchType: 0=Exact, 1=Prefix, 2=Suffix, 3=Glob
    pub path_len: u32,       // Length of the suffix/prefix path pattern
    pub path: [u16; MAX_RULE_PATH_LEN], // UTF-16 character pattern
    pub process_id: u32,     // Process ID to filter (0 = match all processes)
    pub is_exclude_process: u32, // 1 = Exclude (whitelist PID), 0 = Include (blacklist PID)
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileModuleConfig {
    pub timeout_ms: u32,       // Interception timeout in milliseconds
    pub default_action: u32,   // 1 = Allow, 2 = Deny
    pub rule_count: u32,       // Number of active filtering rules
    pub rules: [FileFilterRule; MAX_FILTER_RULES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileDecision {
    pub transaction_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileEvent {
    pub transaction_id: u64,
    pub process_id: u32,
    pub op_code: u32,      // 1=Create, 2=Write, 4=Delete, 8=Rename
    pub path_len: u32,     // Length of path in characters
    pub decision: u32,     // 1 = Allow, 2 = Deny, 3 = Redirect (default initialized to 1)
    pub redirect_path_len: u32,
    pub redirect_path: [u16; MAX_RULE_PATH_LEN],
}
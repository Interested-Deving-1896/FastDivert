use anyhow::{bail, Result};

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Layer {
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
    Transport = 5,
    Stream = 6,
    File = 7,
}

pub enum Flags {
    Divert = 0x0000,
    RecvOnly = 0x0004,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DivertAddress {
    pub timestamp: i64,
    pub flags: u32,
    pub reserved2: u32,
    pub data: DivertAddressData,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertDataNetwork {
    pub if_idx: u32,
    pub sub_if_idx: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct DivertDataFlow {
    pub endpoint_id: u64,
    pub process_id: u32,
    pub filter_id: u32,
    pub layer: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct DivertDataSocket {
    pub endpoint_id: u64,
    pub process_id: u32,
    pub filter_id: u32,
    pub layer: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertDataReflect {
    pub timestamp: i64,
    pub process_id: u32,
    pub filter_id: u32,
    pub layer: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union DivertAddressData {
    pub network: DivertDataNetwork,
    pub flow: DivertDataFlow,
    pub socket: DivertDataSocket,
    pub reflect: DivertDataReflect,
    pub reserved3: [u8; 64],
}

impl DivertAddress {
    // --- Bitfield Getter Methods ---

    pub fn layer(&self) -> u8 {
        (self.flags & 0xFF) as u8
    }

    pub fn event(&self) -> u8 {
        ((self.flags >> 8) & 0xFF) as u8
    }

    pub fn sniffed(&self) -> bool {
        ((self.flags >> 16) & 0x1) != 0
    }

    pub fn outbound(&self) -> bool {
        ((self.flags >> 17) & 0x1) != 0
    }

    pub fn loopback(&self) -> bool {
        ((self.flags >> 18) & 0x1) != 0
    }

    pub fn impostor(&self) -> bool {
        ((self.flags >> 19) & 0x1) != 0
    }

    pub fn ipv6(&self) -> bool {
        ((self.flags >> 20) & 0x1) != 0
    }

    pub fn ip_checksum(&self) -> bool {
        ((self.flags >> 21) & 0x1) != 0
    }

    pub fn tcp_checksum(&self) -> bool {
        ((self.flags >> 22) & 0x1) != 0
    }

    pub fn udp_checksum(&self) -> bool {
        ((self.flags >> 23) & 0x1) != 0
    }

    pub fn reserved1(&self) -> u8 {
        ((self.flags >> 24) & 0xFF) as u8
    }

    // --- Bitfield Setter Methods ---

    pub fn set_layer(&mut self, value: u8) {
        self.flags = (self.flags & !0xFF) | (value as u32 & 0xFF);
    }

    pub fn set_event(&mut self, value: u8) {
        self.flags = (self.flags & !(0xFF << 8)) | ((value as u32 & 0xFF) << 8);
    }

    pub fn set_sniffed(&mut self, value: bool) {
        self.set_bit(16, value);
    }

    pub fn set_outbound(&mut self, value: bool) {
        self.set_bit(17, value);
    }

    pub fn set_ipv6(&mut self, value: bool) {
        self.set_bit(20, value);
    }

    fn set_bit(&mut self, pos: u32, value: bool) {
        if value {
            self.flags |= 1 << pos;
        } else {
            self.flags &= !(1 << pos);
        }
    }
}

pub const MAX_FILTER_RULES: usize = 16;
pub const MAX_RULE_PATH_LEN: usize = 260;

pub const FILE_OP_CREATE: u32 = 1;
pub const FILE_OP_WRITE: u32 = 2;
pub const FILE_OP_DELETE: u32 = 4; // Managed as SetInformation in minifilter

pub const FILE_MATCH_EXACT: u32 = 0;
pub const FILE_MATCH_PREFIX: u32 = 1;
pub const FILE_MATCH_SUFFIX: u32 = 2;
pub const FILE_MATCH_GLOB: u32 = 3;

pub const FILE_ACTION_ALLOW: u32 = 1;
pub const FILE_ACTION_DENY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileFilterRule {
    pub operation_mask: u32,
    pub match_type: u32,     // MatchType: 0=Exact, 1=Prefix, 2=Suffix, 3=Glob
    pub path_len: u32,
    pub path: [u16; MAX_RULE_PATH_LEN],
    pub process_id: u32,     // Process ID to filter (0 = match all processes)
    pub is_exclude_process: u32, // 1 = Exclude (whitelist PID), 0 = Include (blacklist PID)
}

impl Default for FileFilterRule {
    fn default() -> Self {
        Self {
            operation_mask: 0,
            match_type: 0,
            path_len: 0,
            path: [0u16; MAX_RULE_PATH_LEN],
            process_id: 0,
            is_exclude_process: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileModuleConfig {
    pub timeout_ms: u32,
    pub default_action: u32, // 1 = Allow, 2 = Deny
    pub rule_count: u32,
    pub rules: [FileFilterRule; MAX_FILTER_RULES],
}

impl Default for FileModuleConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            default_action: FILE_ACTION_ALLOW,
            rule_count: 0,
            rules: [FileFilterRule::default(); MAX_FILTER_RULES],
        }
    }
}

/// Resolves a Win32 path with a drive letter (e.g., "C:\path") to its NT native device path (e.g., "\Device\HarddiskVolume3\path").
pub fn resolve_win32_path_to_nt(path: &str) -> String {
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        let drive = &path[..2]; // e.g. "C:"
        let mut target_buf = [0u16; 512];
        let mut drive_wide: Vec<u16> = drive.encode_utf16().collect();
        drive_wide.push(0);

        unsafe {
            let len = windows::Win32::Storage::FileSystem::QueryDosDeviceW(
                windows::core::PCWSTR(drive_wide.as_ptr()),
                Some(&mut target_buf),
            );
            if len > 0 {
                let mut end = 0;
                while end < target_buf.len() && target_buf[end] != 0 {
                    end += 1;
                }
                if let Ok(nt_drive) = String::from_utf16(&target_buf[..end]) {
                    let rest = &path[2..];
                    return format!("{}{}", nt_drive, rest);
                }
            }
        }
    }
    path.to_string()
}

impl FileModuleConfig {
    /// Creates a new `FileModuleConfig` with the specified timeout and default action.
    ///
    /// * `timeout_ms`: The interception timeout in milliseconds (e.g., 5000).
    /// * `default_action`: The action to take if a decision is not received before timeout (1 = Allow, 2 = Deny).
    pub fn new(timeout_ms: u32, default_action: u32) -> Self {
        Self {
            timeout_ms,
            default_action,
            rule_count: 0,
            rules: [FileFilterRule::default(); MAX_FILTER_RULES],
        }
    }

    /// Adds a filtering rule with full control over MatchType and Process Filtering.
    /// Matches are automatically converted to NT device paths (e.g. resolving C: to active native volumes).
    ///
    /// * `path`: A Rust string slice representing the path pattern.
    /// * `operation_mask`: Bitmask of operations (e.g., `FILE_OP_CREATE`, `FILE_OP_WRITE`, `FILE_OP_DELETE`).
    /// * `match_type`: MatchType enum value: 0=Exact, 1=Prefix, 2=Suffix, 3=Glob.
    /// * `process_id`: Target process ID to filter (0 = apply to all processes).
    /// * `is_exclude_process`: If true, the specified PID is excluded from matching (whitelisted), otherwise it is included (blacklisted).
    pub fn add_filter(
        mut self,
        path: &str,
        operation_mask: u32,
        match_type: u32,
        process_id: u32,
        is_exclude_process: bool,
    ) -> Result<Self> {
        if self.rule_count as usize >= MAX_FILTER_RULES {
            bail!("Maximum rule limit reached ({})", MAX_FILTER_RULES);
        }

        // Auto-resolve Win32 paths to NT paths
        let resolved_path = resolve_win32_path_to_nt(path);

        let mut wide_path = [0u16; MAX_RULE_PATH_LEN];
        let utf16: Vec<u16> = resolved_path.encode_utf16().collect();
        if utf16.len() > MAX_RULE_PATH_LEN {
            bail!(
                "Resolved NT path length {} exceeds maximum limit of {} characters",
                utf16.len(),
                MAX_RULE_PATH_LEN
            );
        }
        wide_path[..utf16.len()].copy_from_slice(&utf16);

        self.rules[self.rule_count as usize] = FileFilterRule {
            operation_mask,
            match_type,
            path_len: utf16.len() as u32,
            path: wide_path,
            process_id,
            is_exclude_process: if is_exclude_process { 1 } else { 0 },
        };
        self.rule_count += 1;

        Ok(self)
    }
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
    pub op_code: u32,      // 1=Create, 2=Write, 3=SetInfo (Delete/Rename)
    pub path_len: u32,     // Length of path in UTF-16 characters
    pub decision: u32,     // 1 = Allow, 2 = Deny, 3 = Redirect (default initialized to 1)
    pub redirect_path_len: u32,
    pub redirect_path: [u16; MAX_RULE_PATH_LEN],
}

/// User-space decision returned by file event callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileCallbackDecision {
    Allow,
    Deny,
    Redirect(String),
}
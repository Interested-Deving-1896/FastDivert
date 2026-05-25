/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

pub mod ioctl_code;
mod divert;
pub mod driver_install;
pub mod ioctl;
pub mod raw;
pub mod ringbuffer;
mod types;
pub mod bpf_compiler;
pub mod packet_parser;
pub mod utils;

pub use divert::{Divert, DefaultWait, BusyPoll};
pub use ringbuffer::{PacketData, PacketRef, FileEventRef, PollMode, RingBufferClient};
pub use types::{
    DivertAddress, Flags, Layer, FileDecision, FileEvent, FileFilterRule, FileModuleConfig,
    FILE_OP_CREATE, FILE_OP_DELETE, FILE_OP_WRITE,
    FILE_MATCH_EXACT, FILE_MATCH_PREFIX, FILE_MATCH_SUFFIX, FILE_MATCH_GLOB,
    FILE_ACTION_ALLOW, FILE_ACTION_DENY,
    MAX_FILTER_RULES, MAX_RULE_PATH_LEN, FileCallbackDecision,
};
pub use bpf_compiler::{compile_bpf, BpfInsn};
pub use packet_parser::{FiveTuple, PacketParser};
pub use utils::hexdump;

const DEFAULT_DRIVER_NAME: &str = "FastDivert";
const DEFAULT_DRIVER_PATH: &str = "fast_divert.sys";
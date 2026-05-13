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

pub use divert::Divert;
pub use ringbuffer::{PacketData, PacketRef, PollMode, RingBufferClient};
pub use types::{DivertAddress, Flags, Layer};

const DEFAULT_DRIVER_NAME: &str = "FastDivert";
const DEFAULT_DRIVER_PATH: &str = "fast_divert.sys";

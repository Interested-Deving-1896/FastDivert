/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

#![no_std]
#![allow(unused)]

extern crate alloc;
extern crate wdk_panic;

use wdk_alloc::WdkAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

mod context;
mod driver;
mod file;
mod ioctl_handler;
mod ioctl_internal;
mod ioctl_user;
mod network;
pub(crate) mod ringbuffer;
mod wdk_ext;

static DEVICE_NAME: &str = r"\Device\FastDviert";

static DEVICE_DOS_PATH: &str = r"\??\FastDviert";

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        ::wdk::print!("[FastDivert]: ");
        ::wdk::println!($($arg)*)
    }};
}

// for ndis pool etc.
pub const MEMORY_POOL_TAG: u32 = u32::from_le_bytes(*b"Fast");

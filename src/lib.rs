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
mod file_monitor;
mod ioctl_handler;
mod ioctl_internal;
mod ioctl_user;
mod network;
pub(crate) mod ringbuffer;
mod wdk_ext;

static DEVICE_NAME: &str = r"\Device\FastDivert";

static DEVICE_DOS_PATH: &str = r"\??\FastDivert";

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        ::wdk::print!("[FastDivert]: ");
        ::wdk::println!($($arg)*)
    }};
}

// for ndis pool etc.
pub const MEMORY_POOL_TAG: u32 = u32::from_le_bytes(*b"Fast");

pub static mut REGISTRY_PATH: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
pub static mut GLOBAL_DRIVER_OBJECT: *mut wdk_sys::_DRIVER_OBJECT = core::ptr::null_mut();

pub fn set_global_registry_path(path: alloc::vec::Vec<u16>) {
    unsafe {
        REGISTRY_PATH = path;
    }
}

pub fn get_global_registry_path() -> &'static [u16] {
    unsafe {
        let ptr = &raw const REGISTRY_PATH;
        core::slice::from_raw_parts((*ptr).as_ptr(), (*ptr).len())
    }
}

pub fn set_global_driver_object(driver: *mut wdk_sys::_DRIVER_OBJECT) {
    unsafe {
        GLOBAL_DRIVER_OBJECT = driver;
    }
}

pub fn get_global_driver_object() -> *mut wdk_sys::_DRIVER_OBJECT {
    unsafe {
        GLOBAL_DRIVER_OBJECT
    }
}

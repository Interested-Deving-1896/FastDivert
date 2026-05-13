/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Layer {
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
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
#[derive(Debug, Copy, Clone)]
pub struct DivertDataFlow {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertDataSocket {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DivertDataReflect {
    pub timestamp: i64,
    pub process_id: u32,
    pub layer: Layer,
    pub flags: u64,
    pub priority: i16,
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
use crate::ringbuffer::PacketData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
}

pub struct PacketParser;

impl PacketParser {
    #[inline]
    pub fn get_byte(data: &PacketData<'_>, idx: usize) -> Option<u8> {
        match data {
            PacketData::Contiguous(s) => s.get(idx).copied(),
            PacketData::Wrapped { part1, part2 } => {
                if idx < part1.len() {
                    Some(part1[idx])
                } else {
                    part2.get(idx - part1.len()).copied()
                }
            }
        }
    }

    #[inline]
    pub fn get_u16(data: &PacketData<'_>, idx: usize) -> Option<u16> {
        Self::get_byte(data, idx).and_then(|b1| {
            Self::get_byte(data, idx + 1).map(|b2| {
                u16::from_be_bytes([b1, b2])
            })
        })
    }

    #[inline]
    pub fn get_u32(data: &PacketData<'_>, idx: usize) -> Option<u32> {
        Self::get_byte(data, idx).and_then(|b1| {
            Self::get_byte(data, idx + 1).and_then(|b2| {
                Self::get_byte(data, idx + 2).and_then(|b3| {
                    Self::get_byte(data, idx + 3).map(|b4| {
                        u32::from_be_bytes([b1, b2, b3, b4])
                    })
                })
            })
        })
    }

    pub fn extract_5tuple(data: &PacketData<'_>) -> Option<FiveTuple> {
        let len = data.len();
        if len == 0 {
            return None;
        }

        let vhl = Self::get_byte(data, 0)?;
        let version = vhl >> 4;

        if version == 4 {
            if len < 20 {
                return None;
            }
            let ihl = (vhl & 0x0F) as usize * 4;
            if len < ihl {
                return None;
            }

            let proto_byte = Self::get_byte(data, 9)?;
            let src_b1 = Self::get_byte(data, 12)?;
            let src_b2 = Self::get_byte(data, 13)?;
            let src_b3 = Self::get_byte(data, 14)?;
            let src_b4 = Self::get_byte(data, 15)?;
            let dst_b1 = Self::get_byte(data, 16)?;
            let dst_b2 = Self::get_byte(data, 17)?;
            let dst_b3 = Self::get_byte(data, 18)?;
            let dst_b4 = Self::get_byte(data, 19)?;

            let src_ip = IpAddr::V4(Ipv4Addr::new(src_b1, src_b2, src_b3, src_b4));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(dst_b1, dst_b2, dst_b3, dst_b4));

            let (protocol, src_port, dst_port) = match proto_byte {
                6 => {
                    // TCP
                    let p_str = "TCP".to_string();
                    if len >= ihl + 4 {
                        let sp = Self::get_u16(data, ihl)?;
                        let dp = Self::get_u16(data, ihl + 2)?;
                        (p_str, Some(sp), Some(dp))
                    } else {
                        (p_str, None, None)
                    }
                }
                17 => {
                    // UDP
                    let p_str = "UDP".to_string();
                    if len >= ihl + 4 {
                        let sp = Self::get_u16(data, ihl)?;
                        let dp = Self::get_u16(data, ihl + 2)?;
                        (p_str, Some(sp), Some(dp))
                    } else {
                        (p_str, None, None)
                    }
                }
                1 => {
                    // ICMP
                    if len >= ihl + 2 {
                        let icmp_type = Self::get_byte(data, ihl)?;
                        let icmp_code = Self::get_byte(data, ihl + 1)?;
                        (format!("ICMP (type={}, code={})", icmp_type, icmp_code), None, None)
                    } else {
                        ("ICMP".to_string(), None, None)
                    }
                }
                p => (format!("PROTO-{}", p), None, None),
            };

            Some(FiveTuple {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            })
        } else if version == 6 {
            if len < 40 {
                return None;
            }

            let next_header = Self::get_byte(data, 6)?;

            let mut src_bytes = [0u8; 16];
            for i in 0..16 {
                src_bytes[i] = Self::get_byte(data, 8 + i)?;
            }
            let mut dst_bytes = [0u8; 16];
            for i in 0..16 {
                dst_bytes[i] = Self::get_byte(data, 24 + i)?;
            }

            let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

            let (protocol, src_port, dst_port) = match next_header {
                6 => {
                    // TCP
                    let p_str = "TCP".to_string();
                    if len >= 44 {
                        let sp = Self::get_u16(data, 40)?;
                        let dp = Self::get_u16(data, 42)?;
                        (p_str, Some(sp), Some(dp))
                    } else {
                        (p_str, None, None)
                    }
                }
                17 => {
                    // UDP
                    let p_str = "UDP".to_string();
                    if len >= 44 {
                        let sp = Self::get_u16(data, 40)?;
                        let dp = Self::get_u16(data, 42)?;
                        (p_str, Some(sp), Some(dp))
                    } else {
                        (p_str, None, None)
                    }
                }
                58 => {
                    // ICMPv6
                    if len >= 42 {
                        let icmp_type = Self::get_byte(data, 40)?;
                        let icmp_code = Self::get_byte(data, 41)?;
                        (format!("ICMPv6 (type={}, code={})", icmp_type, icmp_code), None, None)
                    } else {
                        ("ICMPv6".to_string(), None, None)
                    }
                }
                p => (format!("PROTO-{}", p), None, None),
            };

            Some(FiveTuple {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            })
        } else {
            None
        }
    }
}

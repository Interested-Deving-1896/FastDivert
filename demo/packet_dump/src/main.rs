/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{Divert, PacketData, PollMode};
use fastdivert::{Flags, Layer};

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

fn main() -> Result<()> {
    println!("Initializing Divert client...");

    let divert = Divert::open("true", Layer::Network as u32, 0, Flags::RecvOnly as u64)
        .context("Failed to initialize Divert from driver")?;

    println!("Divert opened successfully! Starting poll loop...");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Global packet counter
    let packet_count = Arc::new(AtomicUsize::new(0));

    // Setup Ctrl-C handler to exit gracefully
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl-C, stopping...");
        r.store(false, Ordering::SeqCst);
    })
    .context("Error setting Ctrl-C handler")?;

    // Start multi-threaded polling
    let num_threads = 4;
    println!("Starting {} polling threads...", num_threads);

    let count_clone = packet_count.clone();

    let _handles = divert.poll_multi_threads(
        num_threads,
        PollMode::IoctlWait,
        move |_worker_id, packet| {
            // Increment the global counter atomically
            let count = count_clone.fetch_add(1, Ordering::Relaxed) + 1;

            print!(
                "\n[Packet #{}] Core: {}, RecordType: {}, Length: {}, IfIdx: {}, Direction: {}, IPv{}",
                count,
                packet.core_id,
                packet.record_type,
                packet.data.len(),
                unsafe { packet.address.data.network.if_idx },
                if packet.address.outbound() {
                    "outbound"
                } else {
                    "inbound"
                },
                if packet.address.ipv6() { 6 } else { 4 },
            );

            // Parse and print the 5-tuple routing info
            if let Some((src_ip, src_port, dst_ip, dst_port, proto)) = extract_5tuple(&packet.data)
            {
                if proto == "ICMP" || proto == "UNKNOWN" {
                    println!(" | {} {} -> {}", proto, src_ip, dst_ip);
                } else {
                    println!(
                        " | {} {}:{} -> {}:{}",
                        proto, src_ip, src_port, dst_ip, dst_port
                    );
                }
            } else {
                println!(" | (Non-IPv4 or unrecognized packet)");
            }

            // Print the payload in a tcpdump-like format using zero-copy
            print_hexdump(&packet.data);
        },
        || {},
    );

    println!("Press Ctrl-C to exit...");
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    println!(
        "Total packets processed: {}",
        packet_count.load(Ordering::SeqCst)
    );

    Ok(())
}

/// A helper function to print a tcpdump-like hex dump of the packet data
fn print_hexdump(data: &PacketData<'_>) {
    // To achieve zero-copy, we match on the PacketData enum directly
    // and iterate over its underlying slices.
    let (part1, part2) = match data {
        PacketData::Contiguous(s) => (*s, &[] as &[u8]),
        PacketData::Wrapped { part1, part2 } => (*part1, *part2),
    };

    let mut i = 0;
    let mut chars = String::new();
    let max_dump = 64; // Limit to 64 bytes to avoid console flooding

    for chunk in [part1, part2].iter() {
        for &byte in chunk.iter() {
            if i % 16 == 0 {
                if i > 0 {
                    println!("  {}", chars);
                    chars.clear();
                }
                print!("    {:04x}: ", i);
            }

            print!("{:02x} ", byte);

            // Collect ASCII representation
            if byte.is_ascii_graphic() || byte == b' ' {
                chars.push(byte as char);
            } else {
                chars.push('.');
            }

            i += 1;
            if i >= max_dump {
                break;
            }
        }
        if i >= max_dump {
            break;
        }
    }

    // Pad the last line and print the remaining chars
    if i % 16 != 0 {
        let padding = 16 - (i % 16);
        for _ in 0..padding {
            print!("   ");
        }
        println!("  {}", chars);
    } else if i > 0 {
        println!("  {}", chars);
    }

    if data.len() > max_dump {
        println!("    ... (truncated {} bytes)", data.len() - max_dump);
    }
}

/// Helper to parse and extract the 5-tuple from IPv4/TCP/UDP packets
fn extract_5tuple(data: &PacketData<'_>) -> Option<(String, u16, String, u16, &'static str)> {
    let len = data.len();
    if len < 20 {
        return None; // Too small to be a valid IP packet
    }

    // Helper to read a single byte safely from a potentially wrapped buffer
    let get_byte = |idx: usize| -> Option<u8> {
        match data {
            PacketData::Contiguous(s) => s.get(idx).copied(),
            PacketData::Wrapped { part1, part2 } => {
                if idx < part1.len() {
                    part1.get(idx).copied()
                } else {
                    part2.get(idx - part1.len()).copied()
                }
            }
        }
    };

    // Helper to read a big-endian u16
    let get_u16 = |idx: usize| -> Option<u16> {
        let b1 = get_byte(idx)? as u16;
        let b2 = get_byte(idx + 1)? as u16;
        Some((b1 << 8) | b2)
    };

    let vhl = get_byte(0)?;
    let version = vhl >> 4;

    // For simplicity, we only parse IPv4 here. IPv6 parsing could be added similarly.
    if version != 4 {
        return None;
    }

    let ihl = (vhl & 0x0F) * 4;
    let ihl_usize = ihl as usize;
    if len < ihl_usize {
        return None;
    }

    let protocol = get_byte(9)?;

    // IPv4 Source and Destination addresses are at offsets 12 and 16
    let src_ip = format!(
        "{}.{}.{}.{}",
        get_byte(12)?,
        get_byte(13)?,
        get_byte(14)?,
        get_byte(15)?
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        get_byte(16)?,
        get_byte(17)?,
        get_byte(18)?,
        get_byte(19)?
    );

    let (src_port, dst_port, proto_name) = match protocol {
        6 => {
            // TCP
            if len < ihl_usize + 4 {
                return None;
            }
            (get_u16(ihl_usize)?, get_u16(ihl_usize + 2)?, "TCP")
        }
        17 => {
            // UDP
            if len < ihl_usize + 4 {
                return None;
            }
            (get_u16(ihl_usize)?, get_u16(ihl_usize + 2)?, "UDP")
        }
        1 => (0, 0, "ICMP"),
        _ => (0, 0, "UNKNOWN"),
    };

    Some((src_ip, src_port, dst_ip, dst_port, proto_name))
}

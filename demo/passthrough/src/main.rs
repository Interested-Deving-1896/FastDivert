/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{Divert, Layer, PacketParser, DefaultWait};

fn main() -> Result<()> {
    println!("=== FastDivert Zero-Copy Inline Passthrough ===");
    println!("[!] Warning: Packets are actively intercepted and re-injected.");

    // 1. Open standard network layer handle in active intercept mode (flags = 0)
    let divert = Divert::open("true", Layer::Network as u32, 0, 0)
        .context("Failed to initialize Divert from driver")?;
    println!("[+] Interception active. Forwarding all packet traffic inline...");

    // 2. Poll packets and immediately forward/re-inject them back into the stack
    divert.poll(
        |packet| {
            if let Some(ft) = PacketParser::extract_5tuple(&packet.data) {
                println!("  Forwarding: {} {}:{} -> {}:{}", 
                    ft.protocol, ft.src_ip, ft.src_port.unwrap_or(0), ft.dst_ip, ft.dst_port.unwrap_or(0));
            }
            if let Err(e) = divert.send_packet(&packet) {
                eprintln!("  [-] Failed to re-inject packet: {:?}", e);
            }
        },
        DefaultWait(&divert),
    )?;

    Ok(())
}

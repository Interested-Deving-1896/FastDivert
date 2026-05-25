/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{compile_bpf, Divert, Flags, Layer, PacketParser, DefaultWait};

fn main() -> Result<()> {
    println!("=== FastDivert BPF Filter Demo ===");

    // 1. Compile BPF filter (match outbound TCP port 80/HTTP)
    let filter = compile_bpf("outbound & tcp port 80")
        .map_err(|e| anyhow::anyhow!(e))
        .context("Failed to compile BPF filter")?;

    // 2. Open client and load BPF filter into the driver
    let divert = Divert::open("true", Layer::Network as u32, 0, Flags::RecvOnly as u64)
        .context("Failed to initialize Divert from driver")?;
    divert.set_bpf_filter(&filter).context("Failed to set BPF filter")?;
    println!("[+] BPF filter loaded. Monitoring outbound HTTP (port 80) packets...");

    // 3. Poll packets synchronously
    divert.poll(
        |packet| {
            if let Some(ft) = PacketParser::extract_5tuple(&packet.data) {
                println!("  Matched: {} {}:{} -> {}:{}", 
                    ft.protocol, ft.src_ip, ft.src_port.unwrap_or(0), ft.dst_ip, ft.dst_port.unwrap_or(0));
            }
        },
        DefaultWait(&divert),
    )?;

    Ok(())
}
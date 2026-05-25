/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{Divert, Flags, Layer, hexdump, DefaultWait};

fn main() -> Result<()> {
    println!("=== FastDivert TCP Stream Reassembly Monitor ===");

    // Open divert client for STREAM layer
    let divert = Divert::open("true", Layer::Stream as u32, 0, Flags::RecvOnly as u64)
        .context("Failed to initialize Divert from driver")?;
    println!("[+] Monitoring reassembled TCP stream payload...");

    // Poll stream segments synchronously and print payload hex/ASCII
    divert.poll(
        |packet| {
            unsafe {
                let flow_data = packet.address.data.flow;
                println!("  Stream Segment - PID: {} | Size: {} Bytes | Outbound: {}",
                    flow_data.process_id,
                    packet.data.len(),
                    packet.address.outbound()
                );
            }
            hexdump(&packet.data, 64);
        },
        DefaultWait(&divert),
    )?;

    Ok(())
}

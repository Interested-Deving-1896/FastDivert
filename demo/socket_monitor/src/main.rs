/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{Divert, Layer, Flags, DefaultWait};

fn main() -> Result<()> {
    println!("=== FastDivert Socket Layer Monitor ===");

    // Open divert client for SOCKET layer
    let divert = Divert::open("true", Layer::Socket as u32, 0, Flags::RecvOnly as u64)
        .context("Failed to initialize Divert from driver")?;
    println!("[+] Monitoring WFP Socket layer events...");

    // Poll socket events synchronously
    divert.poll(
        |packet| {
            unsafe {
                let socket_data = packet.address.data.socket;
                println!("  Socket Event - PID: {} | IPv6: {} | Outbound: {}",
                    socket_data.process_id,
                    packet.address.ipv6(),
                    packet.address.outbound()
                );
            }
        },
        DefaultWait(&divert),
    )?;

    Ok(())
}
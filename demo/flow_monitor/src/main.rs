/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{Divert, Layer, Flags, DefaultWait};

fn main() -> Result<()> {
    println!("=== FastDivert Flow Layer Monitor ===");

    // Open divert client for FLOW layer
    let divert = Divert::open("true", Layer::Flow as u32, 0, Flags::RecvOnly as u64)
        .context("Failed to initialize Divert from driver")?;
    println!("[+] Monitoring WFP Flow layer events...");

    // Poll flow events synchronously
    divert.poll(
        |packet| {
            unsafe {
                let flow_data = packet.address.data.flow;
                println!("  Flow Event - PID: {} | IPv6: {} | Outbound: {}",
                    flow_data.process_id,
                    packet.address.ipv6(),
                    packet.address.outbound()
                );
            }
        },
        DefaultWait(&divert),
    )?;

    Ok(())
}
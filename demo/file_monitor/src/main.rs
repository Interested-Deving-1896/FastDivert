/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{
    Divert, FileCallbackDecision, FileModuleConfig, DefaultWait,
    FILE_OP_CREATE, FILE_OP_WRITE,
    FILE_MATCH_GLOB, FILE_MATCH_SUFFIX, FILE_ACTION_ALLOW,
};

fn main() -> Result<()> {
    println!("=================================================================");
    println!("              FastDivert File Monitor & Interception             ");
    println!("=================================================================");

    // 1. Configure filtering rules using clear constants instead of magic numbers
    let config = FileModuleConfig::new(5000, FILE_ACTION_ALLOW)
        // Rule 1: Glob / Wildcard Matching (using standard Win32 path)
        .add_filter(r"*_block.txt", FILE_OP_WRITE, FILE_MATCH_GLOB, 0, false)?
        // Rule 2: Explicit Suffix Matching (read-only monitoring of all .log files)
        .add_filter(".log", FILE_OP_CREATE | FILE_OP_WRITE, FILE_MATCH_SUFFIX, 0, false)?;

    // Display the registered rules elegantly
    for i in 0..config.rule_count as usize {
        let rule = &config.rules[i];
        let pattern = String::from_utf16(&rule.path[..rule.path_len as usize]).unwrap_or_default();
        println!("  => Rule #{}: Pattern: \"{}\" | MatchType: {}", 
            i + 1, pattern, rule.match_type
        );
    }

    // 2. Load driver & start file monitor subsystem
    let divert = Divert::open_file(&config).context("Failed to open File Divert layer")?;
    println!("[+] Driver loaded! Monitoring file events in real-time. Press Ctrl+C to exit.");

    // 3. Poll and handle file events synchronously
    divert.poll_file_events(
        |ref_event| {
            let ev = &ref_event.event;
            let op_str = match ev.op_code {
                1 => "CREATE",
                2 => "WRITE",
                3 => "SET_INFO",
                _ => "UNKNOWN",
            };

            println!("  => PID: {} | Op: {} | Path: {}", 
                ev.process_id, op_str, ref_event.path
            );

            if ref_event.path.ends_with(".txt") && ev.op_code == 2 {
                println!("     [*] BLOCKING write to text file.");
                FileCallbackDecision::Deny
            } else {
                FileCallbackDecision::Allow
            }
        },
        DefaultWait(&divert),
    )?;

    Ok(())
}

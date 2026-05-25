/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::Divert;
use fastdivert::{Flags, Layer};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};

/// Use 64-byte alignment to prevent false sharing of CPU cache lines
#[repr(align(64))]
struct PerCpuPacketCount {
    count: AtomicU64,
    bytes: AtomicU64,
}

impl Default for PerCpuPacketCount {
    fn default() -> Self {
        Self {
            count: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }
}

fn main() -> Result<()> {
    let divert = Divert::open("true", Layer::Network as u32, 0, Flags::RecvOnly as u64)
        .context("Failed to initialize Divert from driver")?;

    // 1. Automatically detect the number of logical cores, or allow configuration
    let num_threads = std::thread::available_parallelism()?.get() as u32;
    let packet_counts = Arc::new(
        (0..num_threads)
            .map(|_| PerCpuPacketCount::default())
            .collect::<Vec<_>>(),
    );

    // 2. Introduce run state control for graceful exit
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\nStopping capture...");
    })
    .expect("Error setting Ctrl-C handler");

    println!(
        "Divert opened. CPU cores: {}. Starting poll loop...",
        num_threads
    );

    let pc_clone = Arc::clone(&packet_counts);
    let _handles = divert.poll_multi_threads(
        num_threads,
        move |worker_id, packet| {
            // Get the statistics slot of the current core
            let slot = &pc_clone[worker_id as usize];
            slot.count.fetch_add(1, Ordering::Relaxed);
            // Accumulate packet length (bytes)
            slot.bytes
                .fetch_add(packet.data.len() as u64, Ordering::Relaxed);
        },
        || {
            std::thread::sleep(Duration::from_millis(5));
        },
    );

    let mut last_count = 0;
    let mut last_bytes = 0;
    let mut last_time = Instant::now();

    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));

        let now = Instant::now();
        let duration = now.duration_since(last_time).as_secs_f64();

        // Aggregate statistics from all cores
        let mut current_count = 0;
        let mut current_bytes = 0;
        for pc in packet_counts.iter() {
            current_count += pc.count.load(Ordering::Relaxed);
            current_bytes += pc.bytes.load(Ordering::Relaxed);
        }

        let delta_packets = current_count.saturating_sub(last_count);
        let delta_bytes = current_bytes.saturating_sub(last_bytes);

        let pps = delta_packets as f64 / duration;
        // Calculate bandwidth: convert (bytes * 8) to bits, divide by time to get bps, and finally convert to Mbps
        let mbps = (delta_bytes as f64 * 8.0 / 1_000_000.0) / duration;

        println!(
            "Total: {:>10} | PPS: {:>10.2} | Bandwidth: {:>10.2} Mbps",
            current_count, pps, mbps
        );

        last_count = current_count;
        last_bytes = current_bytes;
        last_time = now;
    }

    Ok(())
}

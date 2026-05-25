/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use anyhow::{Context, Result};
use fastdivert::{
    Divert, FileCallbackDecision, FileModuleConfig, DefaultWait,
    FILE_OP_CREATE, FILE_MATCH_SUFFIX, FILE_ACTION_ALLOW,
};
use std::fs;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    println!("=================================================================");
    println!("             FastDivert Dynamic File Redirection Demo            ");
    println!("=================================================================");

    let detect_name = "redirect_detect.tmp";
    let source_name = "redirect_source.txt";
    let target_name = "redirect_target.txt";

    // Setup temporary files
    fs::write(source_name, "ERROR: Redirection failed!")?;
    fs::write(target_name, "★ SUCCESS ★: Redirected dynamically by FastDivert!")?;

    // 1. Configure filter rules using constants instead of magic numbers
    let config = FileModuleConfig::new(5000, FILE_ACTION_ALLOW)
        .add_filter(detect_name, FILE_OP_CREATE, FILE_MATCH_SUFFIX, 0, false)?
        .add_filter(source_name, FILE_OP_CREATE, FILE_MATCH_SUFFIX, 0, false)?;

    // 2. Load driver & start file subsystem
    let divert = Divert::open_file(&config).context("Failed to open File Divert layer")?;
    println!("[+] Driver loaded! Subsystem running.");

    // Dynamic NT Volume Prefix path shared between threads
    let nt_prefix = Arc::new(Mutex::new(None::<String>));

    // 3. Spawn polling thread to handle redirections
    let divert_clone = divert.clone();
    let nt_prefix_clone = nt_prefix.clone();
    let poll_handle = std::thread::spawn(move || {
        let _ = divert_clone.poll_file_events(|ref_event| {
            let _ev = &ref_event.event;

            // Detect NT prefix when redirect_detect.tmp is touched
            if ref_event.path.ends_with(detect_name) {
                let prefix_len = ref_event.path.len() - detect_name.len();
                let prefix = &ref_event.path[..prefix_len];
                *nt_prefix_clone.lock().unwrap() = Some(prefix.to_string());
                println!("[+] Dynamically detected NT prefix: \"{}\"", prefix);
            }

            // Redirect redirect_source.txt requests to redirect_target.txt
            if ref_event.path.ends_with(source_name) {
                if let Some(ref prefix) = *nt_prefix_clone.lock().unwrap() {
                    let target_path = format!("{}{}", prefix, target_name);
                    println!("[*] Intercepted! Redirecting {} => {}", source_name, target_path);
                    return FileCallbackDecision::Redirect(target_path);
                }
            }

            FileCallbackDecision::Allow
        }, DefaultWait(&divert_clone));
    });

    // 4. Trigger auto-detection & verify redirection
    std::thread::sleep(std::time::Duration::from_millis(300));
    fs::write(detect_name, "detect")?; // Touch detect file

    std::thread::sleep(std::time::Duration::from_millis(300));
    println!("[+] Triggering read on \"{}\" (reparse point redirection)...", source_name);
    let content = fs::read_to_string(source_name)?;
    println!("[✔] Redirection Result Content: \"{}\"\n", content);

    // Clean up
    let _ = fs::remove_file(detect_name);
    let _ = fs::remove_file(source_name);
    let _ = fs::remove_file(target_name);
    drop(divert);
    let _ = poll_handle.join();

    Ok(())
}

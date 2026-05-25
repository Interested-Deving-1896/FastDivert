<div align="center">
  <img src="https://img.shields.io/badge/Status-Beta-orange" alt="Status Beta">
  <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform Windows">
  <img src="https://img.shields.io/badge/License-AGPLv3-green" alt="License">
  <img src="https://img.shields.io/badge/Support-LTS-blue" alt="Support LTS">

  <h1>🚀 FastDivert</h1>
  <p><strong>A driver-backed Windows kernel interception SDK for building professional user-space applications without writing your own drivers.</strong></p>
</div>

---

## Overview

`FastDivert` is a modern, ultra-high-performance Windows kernel-mode framework for **network packet/ file IO** capture,
interception, and injection.

it is designed to process 10Gbps+ network traffic with minimal CPU overhead and low latency.

> [!IMPORTANT]
> This project is currently in **Beta** and is under active development.

---

## Key Features

* ⚡ Ultra-High Performance: Eliminates syscalls and lock contention via zero-copy shared memory, per-core lock-free ring
  buffers, and configurable poll modes (BusyPoll/IoctlWait).

* 🌐 L3/L4 Network Interception: Full support for IPv4/IPv6, stream, socket, and flow-level events, featuring
  high-fidelity traffic capture and dynamic injection capabilities.

* 📂 File I/O Control: Real-time directory monitoring and synchronous file access evaluation (Allow/Deny) with dynamic
  path redirection (STATUS_REPARSE).

* 🛡️ Rust Memory Safety: Built with standard WDK crates, eradicating buffer overflows and use-after-free vulnerabilities
  to ensure kernel-level BSOD resistance.

* 💻 Cross-Architecture: Native support for x64 and ARM64 (Windows on ARM) architectures.

---

## Quick Start

### 1. Requirements

* Windows 10 / 11 / Server (x64 or ARM64)
* Rust toolchain (with WDK build bindings)
* Windows Driver Kit (WDK) installed

### 2. Build the Project

Compile both the kernel driver (`.sys`) and user-mode library (`.dll`) seamlessly:

```bash
cargo wdk build
```

### 3. Run the Demos

> Ensure Windows **Test Signing** is enabled (`bcdedit /set testsigning on` and reboot).

* **Packet Counter**:
  ```bash
  cd demo/packet_count
  cargo run --release
  ```
* **File Monitor**:
  ```bash
  cd demo/file_monitor
  cargo run --release
  ```

---

## Examples

### Network Packet Capture

```rust
use fastdivert::{Divert, Flags, Layer};

fn main() -> anyhow::Result<()> {
    let divert = Divert::open_with_driver_path(
        "true", "FastDivert", "fast_divert.sys", Layer::Network as u32, 0, Flags::RecvOnly as u64,
    )?;

    divert.poll_multi_threads(4, |_, _| {
        // Handle packet data in user-space
    }, || {
        std::thread::sleep(std::time::Duration::from_millis(10));
    });
}
```

### Filesystem Activity Monitor

```rust
use fastdivert::{Divert, FileCallbackDecision, FileModuleConfig, DefaultWait, FILE_OP_WRITE, FILE_MATCH_GLOB, FILE_ACTION_ALLOW};

fn main() -> anyhow::Result<()> {
    let config = FileModuleConfig::new(5000, FILE_ACTION_ALLOW)
        .add_filter(r"*_block.txt", FILE_OP_WRITE, FILE_MATCH_GLOB, 0, false)?;

    let divert = Divert::open_file(&config)?;
    divert.poll_file_events(|ref_event| {
        println!("PID: {} | Path: {}", ref_event.event.process_id, ref_event.path);
        if ref_event.path.ends_with(".txt") {
            FileCallbackDecision::Deny
        } else {
            FileCallbackDecision::Allow
        }
    }, DefaultWait(&divert))?;
}
```

---

## Benchmarks

### Environment

- **CPU**: AMD Ryzen 9 9900X3D (8 vCPUs allocated in VMware Workstation)
- **OS**: Windows Server 2025
- **Network Adapter**: VMware VMXNET3

### Performance Data

Tested using `demo/packet_count` under high network load.

| Scenario                                           | Throughput                                      | Resource Usage           |
|:---------------------------------------------------|:------------------------------------------------|:-------------------------|
| **Packet Counting**<br/>(Traffic: Ubuntu `pktgen`) | 100,000 Pkts/s (100Kpps)<br/>~1 Gbps (1500 MTU) | **CPU Utilization ≤ 1%** |

---

## UseCases

#### 1. Next-Gen Endpoint Security (EDR, DLP, & Ransomware Defense)

* **What**: Real-time synchronous tracking and active blocking of file write/creation activities combined with network
  socket monitoring.
* **Value**: Instantly detects and halts unauthorized file encryption (Ransomware behavior) or exfiltration (Data Loss
  Prevention) with authoritative kernel-level intervention before any data leaves the host.

#### 2. Zero Trust & Network Security (ZTNA & NGFW Agents)

* **What**: Transparent redirection of specific local/remote network traffic to user-space security proxies without
  changing system-wide proxy settings.
* **Value**: Enables seamless micro-segmentation, identity-based access control, and inline deep-packet inspection (DPI)
  with zero context-switch bottlenecks.

#### 3. Low-Latency Infrastructure (Gaming & Financial Trading)

* **What**: Sub-microsecond packet capture, modification, and batch injection directly from user-space threads pinned to
  CPU cores.
* **Value**: Delivers ultra-low latency game acceleration (VPNs) and high-frequency trading gateway connections with
  zero packet drop rates.

#### 4. Virtualization & Secure Sandbox Environments

* **What**: Real-time filesystem path redirection (`STATUS_REPARSE`) based on process ID tracking.
* **Value**: Easily isolates untrusted applications by transparently redirecting their file modifications to a secure,
  ephemeral directory without virtual machine overhead.

---
## License

This project is **dual-licensed**.

* **Open Source Option**: Licensed under the AGPLv3 License.
* **Commercial Option**: Please contact the author for commercial licensing.

## Contact

If you have any questions, feedback, please feel free to reach out:

* **GitHub Issues**: For bug reports and feature requests.
* **Email**: [hello@one-api.net](mailto:hello@one-api.net)
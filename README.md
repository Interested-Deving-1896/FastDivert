<div align="center">
  <img src="https://img.shields.io/badge/Status-Beta-orange" alt="Status Beta">
  <img src="https://img.shields.io/badge/Platform-Windows-blue" alt="Platform Windows">
  <img src="https://img.shields.io/badge/License-AGPLv3-green" alt="License">

  <h1>🚀 FastDivert</h1>
  <p><strong>An ultra-high-performance, zero-copy Windows network interception framework written in Rust.</strong></p>
</div>

<p align="center">
  <a href="#overview">Overview</a> |
  <a href="#features">Features</a> |
  <a href="#benchmarks">Benchmarks</a> |
  <a href="#architecture">Architecture</a> |
  <a href="#use-cases">Use Cases</a> |
  <a href="#quick-start">Quick Start</a> |
  <a href="#poll-modes">Poll Modes</a>
</p>

## Overview

`FastDivert` is a modern, ultra-high-performance Windows kernel-mode framework for network packet capture, interception,
and injection.

> [!IMPORTANT]
> This project is currently in **Beta**. While core features are stable, the API may change, and it is recommended for
> testing and development environments only.

Built on the Windows Filtering Platform (WFP) and written entirely in **Rust**, it
is designed to process **10Gbps+** network traffic with minimal CPU overhead and low latency.

This project is inspired by WinDivert and provides a WinDivert-like interface.

## Features

* ⚡ **Ultra Performance (Zero-Copy)**: Bypasses traditional syscall and copy overhead. Uses shared memory mapped
  directly between kernel and user space for sub-microsecond latency. (See Benchmarks)
* 🛡️ **Memory Safe (Rust)**: Developed using the official `wdk` crate ecosystem, leveraging Rust's strict ownership
  model to prevent kernel panics (BSODs) caused by buffer overflows or use-after-free bugs.
* 🚀 **Native Multi-threaded Scaling**: Built for modern multi-core CPUs. It creates independent lock-free ring buffers
  per core, allowing parallel processing without global lock contention.
* 🔋 **Flexible Poll Modes**: Choose between ultra-low latency `BusyPoll` or CPU-efficient `IoctlWait` modes.
* 💻 **Cross-Architecture**: Native support for both **x64** and **ARM64** (Windows on ARM) architectures.
* 🎯 **WFP Integration**: Robust packet interception using the official Windows Filtering Platform API.
* 🔌 **User-Mode Library**: Comes with a safe, easy-to-use Rust user-mode DLL (`fastdivert` crate) for rapid application
  development.
* 🔍 **Process ID Tracking (WIP)**: Ability to associate network packets with the originating process ID for both
  filtering and packet processing.

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

## Use Cases

* **High-Performance Firewalls**: Stateful or stateless packet filtering at line rate.
* **Game Accelerators & Proxies**: Low-latency traffic redirection and optimization.
* **Intrusion Detection/Prevention (IDS/IPS)**: Deep packet inspection (DPI) without context-switch bottlenecks.
* **Network Monitoring**: Zero-copy packet capture for high-bandwidth traffic analysis.
* **Traffic Shapers**: Precision bandwidth control and QoS enforcement.

## Supported WFP Layers

Currently implemented and tested:

* **Network Layer**: IPv4 support.

*Upcoming / Experimental:*

* **IP Forward Layer**: For routing and gateway applications.
* **Transport Layer** (TCP/UDP segments)
* **Stream Layer** (Continuous TCP data)
* **Flow & Socket Layers** (ALE Auth/Connect)

## Architecture

1. **Kernel Driver (`.sys`)**: Registers WFP Callouts. When a packet matches, it is transferred directly into a
   lock-free
   ring buffer in shared memory.
2. **User-mode Application**: Maps the shared memory. Polls the ring buffer directly from user space without
   transitioning to kernel mode for every packet.
3. **Injection**: Modified or newly crafted packets are placed back into the shared memory, and a single signal is sent
   to the driver to batch-inject them back into the network stack.

## Documentation

Detailed documentation is currently **Work in Progress (WIP)**.

* Architecture Deep Dive (Coming Soon)
* API Reference (Coming Soon)
* Driver Security & Signing

## Poll Modes

FastDivert provides different polling strategies to balance performance and power consumption:

| Mode                          | Strategy                                          | Use Case                                                                              |
|:------------------------------|:--------------------------------------------------|:--------------------------------------------------------------------------------------|
| `BusyPoll`                    | CPU constantly checks the ring buffer.            | **Lowest latency (<1μs)**. Ideal for high-frequency 10Gbps+ trading or firewall apps. |
| `IoctlWait`(Wakeup on packet) | Uses Windows Kernel Events to wake up the thread. | **Low CPU usage**. Suitable for background monitoring or lower-bandwidth tasks.       |

The recommended best practice is to use `BusyPoll` with short sleep intervals (as shown in the examples) to achieve a
balance between high performance and CPU efficiency.

## Requirements

* **OS**: Windows 10 / Windows 11 / Windows Server (x64/ARM64).
* **Compiler**: Rust toolchain (nightly may be required by `wdk`).
* **WDK**: Windows Driver Kit installed and integrated with Visual Studio.

## Building

This project is built using Cargo, seamlessly integrated with Microsoft's `wdk-build` scripts.

```bash
cargo wdk build
```

*(This builds both the kernel driver `.sys` and the user-mode library).*

## Quick Start

> **Note**: Running custom drivers requires enabling Test Signing mode in Windows or obtaining a valid EV code signing
> certificate.

1. **Enable Test Signing**:
   Open an Administrator Command Prompt and run:
   ```cmd
   bcdedit /set testsigning on
   ```
   *(Reboot your computer for the change to take effect).*

2. **Run the Demo (Auto-Installs Driver)**:
   The user-mode library handles loading the driver automatically if it's placed in the same directory.

   Run the high-performance packet counting demo:
   ```bash
   cd demo/packet_count
   cargo run --release
   ```

   Or the tcpdump-like hex dumper:
   ```bash
   cd demo/packet_dump
   cargo run --release
   ```

## Examples

### Simple Packet Counting Example

```rust
use fastdivert::{Divert, Flags, Layer, PollMode};
use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    // Open Divert handle with multi-threaded support
    let divert = Divert::open_with_driver_path(
        "true",                  // Filter string (e.g., true for all)
        "FastDivert",
        "fast_divert.sys",
        Layer::Network as u32,
        0,
        Flags::RecvOnly as u64,
    )?;

    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);

    divert.poll_multi_threads(4, PollMode::BusyPoll, move |_, _| {
        c.fetch_add(1, Ordering::Relaxed);
    }, || {
        std::thread::sleep(Duration::from_millis(10));
    });

    loop {
        println!("Packets: {}", count.load(Ordering::Relaxed));
        std::thread::sleep(Duration::from_secs(1));
    }
}

```

More examples and other languages are on the way.

## Roadmap & TODOs

* [ ] **BPF-like Filter Compiler**: Implement in-kernel filtering strings (e.g., `tcp.dstport == 80`) using a safe
  interpreter to discard unwanted packets *before* they enter the ring buffer.
* [ ] **Application Layer Enforcement (ALE)**: Support for process-based filtering and socket-level interception.
* [ ] **Packet Redirection**: Native kernel-mode redirection to different local ports or remote addresses.
* [ ] **Advanced Flow Context**: Support for maintaining stateful flow data within the kernel buffer.
* [ ] **Language Bindings**: Native library for Rust and Golang, and a dynamic library (C-ABI) wrapper for other
  languages.

## License

This project is **dual-licensed**.

* **Open Source Option**: Licensed under the AGPLv3 License.
* **Commercial Option**: Please contact the author for commercial licensing.

## Contact

If you have any questions, feedback, please feel free to reach out:

* **GitHub Issues**: For bug reports and feature requests.
* **Email**: [hello@one-api.net](mailto:hello@one-api.net)
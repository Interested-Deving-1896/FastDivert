/*
 * Copyright (c) 2026 github.com/one-api. All rights reserved.
 * Licensed under AGPLv3 (https://www.gnu.org/licenses/agpl-3.0.html) or a commercial license.
 * See: https://github.com/one-api/FastDivert#license
 */

use bindgen;
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), wdk_build::ConfigError> {
    let sdk_version = "10.0.26100.0";
    let include_base = format!(
        r"C:\Program Files (x86)\Windows Kits\10\Include\{}",
        sdk_version
    );
    let bindings = bindgen::Builder::default()
        .header("src/wdk_ext/wrapper.h")
        .use_core()
        // --- Fix "No Target Architecture" ---
        .clang_arg("-D_AMD64_")
        .clang_arg("-DNTDDI_VERSION=0x0A000000")
        .clang_arg("-D_WIN32_WINNT=0x0A00")
        .clang_arg("-D_KERNEL_MODE")
        // For MSVC
        .clang_arg("-fms-extensions")
        .clang_arg("-fms-compatibility")
        .clang_arg("-Wno-microsoft-enum-forward-reference") // ignore enum warning
        // Set include path
        .clang_arg(format!("-I{}/km", include_base))
        .clang_arg(format!("-I{}/km/ndis", include_base))
        .clang_arg(format!("-I{}/shared", include_base))
        .clang_arg(format!("-I{}/um", include_base))
        .clang_arg(format!("-I{}/ndis", include_base))
        // --- Set target ---
        .clang_args(&["-target", "x86_64-pc-windows-msvc"])
        //
        .allowlist_function("Ndis.*")
        .allowlist_function("Fwps.*")
        .allowlist_function("Fwpm.*")
        //
        .allowlist_type("FWPM_CALLOUT.*")
        .allowlist_type("FWPS_.*")
        .allowlist_type("FWPM.*")
        .allowlist_type("MDL")
        .allowlist_type("PMDL")
        //
        .allowlist_var("FWPS_.*")
        .allowlist_var("FWPM.*")
        .allowlist_var("NET_.*")
        .allowlist_var("NDIS_.*")
        .allowlist_var("FWP_.*")
        //
        .blocklist_type("GUID")
        .blocklist_type("HANDLE")
        .blocklist_type("PMDL")
        // .blocklist_type("FWPM_ACTION0")
        .manually_drop_union(".*")
        //
        .layout_tests(false) //todo:?
        .derive_default(true) // add default for struct
        // .wrap_static_fns(true) // for disable some warnings
        .generate()
        .expect("failed to generate NDIS bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("ndis_bindings.rs"))
        .ok();

    println!("cargo:rustc-link-lib=ntoskrnl");
    println!("cargo:rustc-link-lib=fwpkclnt");
    println!("cargo:rustc-link-lib=ndis");
    println!("cargo:rustc-link-lib=uuid");
    println!("cargo:rustc-link-lib=wdm");

    wdk_build::configure_wdk_binary_build()
}

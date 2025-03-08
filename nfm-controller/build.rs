// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cargo_metadata::MetadataCommand;
use std::path::Path;
use std::process::Command;
use which::which;

fn main() -> shadow_rs::SdResult<()> {
    // We skip the eBPF build if running under tarpaulin, which measures code test coverage.
    // tarpaulin is incompatible with `no_std` and BPF's different target architecture.
    let should_build_ebpf = std::env::var("CARGO_CFG_TARPAULIN").is_err();

    if should_build_ebpf {
        set_up_toolchain();
        let release = std::env::var("PROFILE").unwrap() == "release";
        build_ebpf(release);
    }

    shadow_rs::new()
}

fn set_up_toolchain() {
    Command::new("rustup")
        .args(["component", "add", "rust-src"])
        .status()
        .expect("Failed to add rust-src");

    if Command::new("bpf-linker")
        .arg("--version")
        .output()
        .is_err()
    {
        Command::new("cargo")
            .args(["install", "bpf-linker"])
            .status()
            .expect("Failed to install bpf-linker");
    }

    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}

fn build_ebpf(release: bool) {
    let metadata = MetadataCommand::new()
        .manifest_path("../Cargo.toml")
        .exec()
        .expect("Failed to get cargo metadata");

    let target_dir = Path::new("..").canonicalize().unwrap().join("target/ebpf");
    let target_triple = metadata.workspace_metadata["bpf_target"]
        .as_str()
        .expect("Failed to get BPF target triple");

    let bpf_obj_path = target_dir
        .join(target_triple)
        .join(if release { "release" } else { "debug" })
        .join("nfm-bpf");
    println!(
        "cargo:rustc-env=BPF_OBJECT_PATH={}",
        bpf_obj_path.to_str().unwrap()
    );

    let target_trip_arg = format!("--target={}", &target_triple);
    let target_dir_arg = format!("--target-dir={}", target_dir.to_str().unwrap());
    let mut args = vec![
        "build",
        "--manifest-path=../nfm-bpf/Cargo.toml",
        &target_trip_arg,
        &target_dir_arg,
        "-Z",
        "build-std=core",
    ];
    if release {
        args.push("--release");
    }
    let status = Command::new("cargo")
        .env("RUSTC_BOOTSTRAP", "1")
        .env("RUSTFLAGS", "")
        .args(&args)
        .status()
        .expect("Failed to build eBPF program");
    assert!(status.success());
    println!("cargo:rerun-if-changed=../nfm-bpf/**");
}

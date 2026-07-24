// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Cargo command setup for isolated compile fixtures.

use std::{
    env,
    ffi::OsStr,
    process::Command,
};

/// Builds a Cargo command without inheriting the parent coverage wrapper.
///
/// Isolated fixture artifacts are not report inputs for the parent
/// `cargo-llvm-cov` invocation. Instrumenting them produces unmatched profiles
/// that dilute region coverage for the proc-macro crate.
///
/// # Parameters
///
/// * `program` - Cargo executable selected by the test environment.
///
/// # Returns
///
/// A command that preserves ordinary caller configuration and removes only
/// cargo-llvm-cov's private instrumentation variables when coverage is active.
#[allow(dead_code)]
pub fn command(program: &OsStr) -> Command {
    let mut command = Command::new(program);
    if env::var_os("CARGO_LLVM_COV").is_some() {
        for variable in [
            "LLVM_PROFILE_FILE",
            "__CARGO_LLVM_COV_RUSTC_WRAPPER",
            "__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS",
            "__CARGO_LLVM_COV_RUSTC_WRAPPER_CRATE_NAMES",
            "RUSTC_WRAPPER",
            "CARGO_LLVM_COV",
            "CARGO_LLVM_COV_SHOW_ENV",
            "CARGO_LLVM_COV_TARGET_DIR",
            "CARGO_LLVM_COV_BUILD_DIR",
        ] {
            command.env_remove(variable);
        }
    }
    command
}

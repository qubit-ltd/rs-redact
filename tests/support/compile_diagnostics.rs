// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured rustc diagnostics for isolated negative compilation tests.

use std::path::Path;

use serde_json::Value;
use serde_json::from_str;

/// Matches an actual error at the dependent fixture's source, never Cargo's
/// package-resolution or toolchain diagnostics.
///
/// `stdout` must come from Cargo's `--message-format=json` output. The error
/// must match `expected_code` when supplied, mention `expected`, and have a
/// primary span in `src/main.rs` belonging to the fixture binary. Invalid JSON,
/// warnings, dependency errors, and Cargo failures do not establish API
/// rejection.
///
/// # Parameters
///
/// * `stdout`: Cargo's JSON diagnostic stream.
/// * `expected`: The API symbol or diagnostic text required in the error.
/// * `expected_code`: An optional exact rustc error code.
///
/// # Returns
///
/// Whether at least one fixture-source compiler error satisfies every
/// condition.
#[must_use]
pub fn source_error_matches(stdout: &[u8], expected: &str, expected_code: Option<&str>) -> bool {
    String::from_utf8_lossy(stdout).lines().any(|line| {
        let Ok(event) = from_str::<Value>(line) else {
            return false;
        };
        let message = &event["message"];
        event["reason"] == "compiler-message"
            && event["target"]["src_path"]
                .as_str()
                .is_some_and(|path| Path::new(path).ends_with("src/main.rs"))
            && message["level"] == "error"
            && expected_code.is_none_or(|code| message["code"]["code"].as_str() == Some(code))
            && message["message"].as_str().is_some_and(|text| text.contains(expected))
            && message["spans"].as_array().is_some_and(|spans| {
                spans.iter().any(|span| {
                    span["is_primary"] == true
                        && span["file_name"]
                            .as_str()
                            .is_some_and(|path| Path::new(path).ends_with("src/main.rs"))
                })
            })
    })
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public argv module boundary.

use std::ffi::OsStr;

use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::formats::argv::ArgvRedactor;
/// Verifies the module reexports compose into a safe redacted argv view.
#[test]
fn test_argv_module_reexports_compose() {
    let rendered = ArgvRedactor::default()
        .redact_items([ArgvItem::sensitive(
            OsStr::new("raw-secret"),
            Sensitivity::Secret,
        )])
        .to_string();

    assert!(!rendered.contains("raw-secret"));
}

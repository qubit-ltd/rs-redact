// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public text module boundary.

use qubit_redact::Redactor;
/// Verifies redacted and log-safe text reexports compose at the log boundary.
#[test]
fn test_text_module_reexports_compose() {
    let rendered = Redactor::default()
        .redact_field("message", "visible\nforged")
        .escape_for_log()
        .to_string();

    assert_eq!(rendered, r"visible\nforged");
}

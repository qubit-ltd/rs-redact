// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::{DiagnosticBudget, RedactionPolicy, Redactor, argv::ArgvItem};

/// Verifies the argv builder exposes its diagnostic truncation marker.
#[test]
fn test_redacted_argv_builder_renders_input_truncation_marker() {
    let budget = DiagnosticBudget::new(8, 64).expect("the small diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the bounded policy should be valid");
    let rendered = qubit_redact::ArgvRedactor::new(Redactor::new(policy))
        .redact_items([ArgvItem::plain(OsStr::new("uninspected-secret"))])
        .to_string();

    assert_eq!(rendered, r#"["<truncated>"]"#);
}

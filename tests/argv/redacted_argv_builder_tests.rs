// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::argv::ArgvItem;
use qubit_redact::argv::ArgvRedactor;
/// Verifies the argv builder exposes its diagnostic truncation marker.
#[test]
fn test_redacted_argv_builder_renders_input_truncation_marker() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(8)
        .max_output_bytes(64)
        .build()
        .expect("the small diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the bounded policy should be valid");
    let rendered = ArgvRedactor::new(Redactor::new(policy))
        .redact_items([ArgvItem::plain(OsStr::new("uninspected-secret"))])
        .to_string();

    assert_eq!(rendered, r#"["<truncated>"]"#);
}

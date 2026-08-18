// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`ArgvItem`](qubit_redact::formats::argv::ArgvItem).

use std::ffi::OsStr;

use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::formats::argv::ArgvRedactor;
/// Verifies that plain argument items are rendered unchanged by explicit mode.
#[test]
fn test_argv_item_plain_is_rendered_without_masking() {
    let rendered = ArgvRedactor::default()
        .redact_items([ArgvItem::plain(OsStr::new("client"))])
        .to_string();

    assert_eq!(rendered, r#"["client"]"#);
}

/// Verifies debug output exposes metadata without the raw argument value.
#[test]
fn test_argv_item_debug_does_not_expose_value() {
    let rendered = format!("{:?}", ArgvItem::plain(OsStr::new("debug-argument-secret")),);

    assert!(!rendered.contains("debug-argument-secret"), "{rendered}");
    assert!(rendered.contains("value_len"));
    assert!(rendered.contains("sensitivity"));
}

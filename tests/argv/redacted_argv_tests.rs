// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::ArgvRedactor;
use qubit_redact::argv::ArgvItem;
/// Verifies that rendered argv output is safe to display.
#[test]
fn test_redacted_argv_display_is_safe() {
    let rendered = ArgvRedactor::default().redact_items([ArgvItem::plain(OsStr::new("client"))]);
    assert_eq!(rendered.to_string(), r#"["client"]"#);
}

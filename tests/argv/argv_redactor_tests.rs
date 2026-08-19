// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

#[test]
fn redactor_convenience_uses_explicit_argv_mode() {
    let output = Redactor::standard().redact_argv([
        ArgvItem::plain(OsStr::new("plain")),
        ArgvItem::sensitive(OsStr::new("raw"), Sensitivity::Secret),
    ]);

    assert!(output.text().as_str().contains("plain"));
    assert!(!output.text().as_str().contains("raw"));
}

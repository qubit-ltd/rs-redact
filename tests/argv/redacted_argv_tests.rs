// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

#[test]
fn argv_transaction_output_is_log_safe() {
    let output = Redactor::standard().redact_argv([ArgvItem::plain(OsStr::new("safe\nvalue"))]);

    assert!(!output.text().as_str().contains('\n'));
    assert!(output.text().as_str().contains(r"\n"));
}

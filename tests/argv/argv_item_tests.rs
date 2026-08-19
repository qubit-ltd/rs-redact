// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

#[test]
fn argv_item_debug_exposes_metadata_without_raw_value() {
    let item = ArgvItem::sensitive(OsStr::new("debug-argument-secret"), Sensitivity::Secret);
    let rendered = format!("{item:?}");

    assert!(!rendered.contains("debug-argument-secret"));
    assert!(rendered.contains("value_len"));
    assert!(rendered.contains("sensitivity"));
}

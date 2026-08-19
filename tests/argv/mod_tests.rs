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
fn argv_module_exports_transaction_adapter_types() {
    let mut session = Redactor::standard().session();
    session.argv(|argv| {
        argv.items([ArgvItem::plain(OsStr::new("client"))]);
    });
    assert_eq!(session.finish().text().as_str(), r#"["client"]"#);
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

#[test]
fn argv_rendering_is_bounded_by_the_transaction_policy() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(2);
        })
        .expect("limits draft")
        .build()
        .expect("policy");
    let mut session = Redactor::new(policy).session();
    session.argv(|argv| {
        argv.items([ArgvItem::plain(OsStr::new("client"))]);
    });
    let output = session.finish();

    assert!(output.text().as_str().len() <= 2);
}

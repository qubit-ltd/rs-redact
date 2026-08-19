// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration coverage for policy-backed transaction-session composition.

use std::ffi::OsStr;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

#[test]
fn test_redactor_session_composes_policy_classified_fields_and_formats() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("password");
        })
        .expect("field policy draft should build")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let first = session
        .literal("request password=")
        .field("password", "super-secret")
        .literal(" argv=")
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .finish();

    assert_eq!(first.text().as_str(), "request password=<redacted> argv=[\"client\"]");
    assert!(!first.text().as_str().contains("super-secret"));

    // `finish` publishes the transaction and immediately makes the same
    // session ready for a separately accounted next transaction.
    let second = session.field("password", "second-secret").finish();
    assert_eq!(second.text().as_str(), "<redacted>");
    assert!(!second.text().as_str().contains("second-secret"));
}

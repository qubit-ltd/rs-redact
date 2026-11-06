// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public argv heuristic redaction behavior.

use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use qubit_redact::RedactionCompletion;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

/// Covers explicit metadata, assignments, inline options, JVM properties,
/// and replacement of a pending sensitive option.
#[test]
fn test_heuristic_rendering_covers_supported_sensitive_shapes() {
    let output = Redactor::standard()
        .text_composer()
        .argv(|argv| {
            argv.heuristic_items([
                ArgvItem::sensitive(OsStr::new("explicit"), Sensitivity::Secret),
                ArgvItem::plain(OsStr::new("password=assignment")),
                ArgvItem::plain(OsStr::new("--token=inline")),
                ArgvItem::plain(OsStr::new("-Dpassword=jvm")),
                ArgvItem::plain(OsStr::new("--password")),
                ArgvItem::plain(OsStr::new("--token")),
                ArgvItem::plain(OsStr::new("pending")),
                ArgvItem::plain(OsStr::new("=plain")),
                ArgvItem::plain(OsStr::new("-D=plain")),
            ]);
        })
        .finish();

    for secret in ["explicit", "assignment", "inline", "jvm", "pending"] {
        assert!(!output.text().as_str().contains(secret), "output exposed {secret}");
    }
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Non-Unicode input keeps the following value secret through the public
/// writer.
#[cfg(unix)]
#[test]
fn test_heuristic_rendering_fails_closed_for_non_utf8_items() {
    let value = OsString::from_vec(vec![0xff]);
    let output = Redactor::standard()
        .text_composer()
        .argv(|argv| {
            argv.heuristic_items([ArgvItem::plain(&value), ArgvItem::plain(OsStr::new("tail"))]);
        })
        .finish();
    assert!(
        !output.text().as_str().contains("tail"),
        "opaque input must mask the following value"
    );
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::ArgvRedactor;
use qubit_redact::Sensitivity;
use qubit_redact::argv::ArgvItem;
/// Verifies that the argv redactor masks a heuristic password value.
#[test]
fn test_argv_redactor_masks_password_value() {
    let rendered = ArgvRedactor::default()
        .redact_heuristically([
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("raw")),
        ])
        .to_string();
    assert!(!rendered.contains("raw"));
}

/// Verifies the complete supported heuristic syntax remains explicit.
#[test]
fn test_argv_redactor_supports_documented_heuristic_forms() {
    let rendered = ArgvRedactor::default()
        .redact_heuristically([
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("separate-long")),
            ArgvItem::plain(OsStr::new("--password=inline-long")),
            ArgvItem::plain(OsStr::new("-password")),
            ArgvItem::plain(OsStr::new("separate-single")),
            ArgvItem::plain(OsStr::new("PASSWORD=assignment")),
            ArgvItem::sensitive(
                OsStr::new("authoritative"),
                Sensitivity::Secret,
            ),
        ])
        .to_string();

    for secret in [
        "separate-long",
        "inline-long",
        "separate-single",
        "assignment",
        "authoritative",
    ] {
        assert!(!rendered.contains(secret));
    }
}

/// Verifies JVM properties with sensitive names are redacted heuristically.
#[test]
fn test_argv_redactor_masks_sensitive_jvm_property() {
    let rendered = ArgvRedactor::default()
        .redact_heuristically([ArgvItem::plain(OsStr::new(
            "-Dpassword=jvm-secret",
        ))])
        .to_string();

    assert!(rendered.contains("-Dpassword=<redacted>"));
    assert!(!rendered.contains("jvm-secret"));
}

/// Verifies compact options and shell payloads are not inferred by the
/// command-agnostic heuristic.
#[test]
fn test_argv_redactor_keeps_documented_unsupported_forms_plain() {
    let rendered = ArgvRedactor::default()
        .redact_heuristically([
            ArgvItem::plain(OsStr::new("-pSECRET")),
            ArgvItem::plain(OsStr::new("echo --password shell-secret")),
        ])
        .to_string();

    assert!(rendered.contains("-pSECRET"));
    assert!(rendered.contains("shell-secret"));
}

/// Verifies explicit sensitivity remains authoritative for unsupported forms.
#[test]
fn test_argv_redactor_masks_unsupported_forms_when_explicitly_sensitive() {
    let rendered = ArgvRedactor::default()
        .redact_heuristically([
            ArgvItem::sensitive(OsStr::new("-pSECRET"), Sensitivity::Secret),
            ArgvItem::sensitive(
                OsStr::new("-Dpassword=SECRET"),
                Sensitivity::Secret,
            ),
            ArgvItem::sensitive(
                OsStr::new("echo --password shell-secret"),
                Sensitivity::Secret,
            ),
        ])
        .to_string();

    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains("shell-secret"));
}

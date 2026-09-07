// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Process components share the enclosing composer's publication boundary.

use std::ffi::OsStr;

use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

/// Verifies process components are appended to the one borrowed transaction.
#[test]
fn test_command_appends_redacted_argv_and_environment_to_parent_session() {
    let arguments = [
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("argv-secret")),
    ];
    let variables = [(OsStr::new("PASSWORD"), OsStr::new("env-secret"))];

    let output = Redactor::strict()
        .text_composer()
        .process(|process| {
            process.command(OsStr::new("client"), arguments, variables);
        })
        .finish();

    assert!(!output.text().as_str().contains("argv-secret"));
    assert!(!output.text().as_str().contains("env-secret"));
}

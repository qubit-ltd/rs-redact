// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::formats::argv::RedactedArgv;

#[test]
fn session_stages_direct_argv_result() {
    fn assert_result_traits<T: Clone + std::fmt::Debug + Eq>() {}
    assert_result_traits::<RedactedArgv>();

    let redactor = Redactor::default();
    let mut session = redactor.session();
    let _ = session.argv(|argv| {
        argv.redact_items("argv", [ArgvItem::plain(OsStr::new("client"))]);
    });
    let output = session.finish().expect("session should commit");
    assert_eq!(output.get("argv").unwrap().text().as_str(), r#"["client"]"#);
    assert_eq!(
        output.get("argv").unwrap().summary().completion(),
        RedactionCompletion::Complete
    );
}

#[test]
fn session_processes_each_finite_adapter_independently() {
    let redactor = Redactor::default();
    let mut session = redactor.session();
    let _ = session.argv(|argv| {
        argv.redact_items("argv", [ArgvItem::plain(OsStr::new("client"))]);
    });
    let _ = session.argv(|argv| {
        argv.redact_items("other", [ArgvItem::plain(OsStr::new("worker"))]);
    });
    let output = session.finish().expect("session should commit");
    assert!(output.text().as_str().contains("client"));
    assert!(output.text().as_str().contains("worker"));
    assert_eq!(output.results().len(), 2);
}

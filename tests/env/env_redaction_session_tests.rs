// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================

use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::Redactor;
use qubit_redact::formats::env::RedactedEnv;
use qubit_redact::formats::env::RedactedEnvPair;

#[test]
fn session_stages_direct_environment_results() {
    fn assert_result_traits<T: Clone + std::fmt::Debug + Eq>() {}
    assert_result_traits::<RedactedEnvPair>();
    assert_result_traits::<RedactedEnv>();
    let redactor = Redactor::default();
    let mut session = redactor.session();
    let _ = session.env(|env| {
        env.redact_pair_as("pair", "MODE", "debug");
        env.redact_os_pairs_as("list", [(OsStr::new("MODE"), OsStr::new("debug"))]);
    });
    let output = session.finish().expect("session should commit");
    assert_eq!(output.get("pair").unwrap().text().as_str(), "MODE=debug");
    assert_eq!(output.get("list").unwrap().text().as_str(), r#"["MODE=debug"]"#);
    assert_eq!(
        output.get("pair").unwrap().summary().completion(),
        RedactionCompletion::Complete
    );
}

#[test]
fn duplicate_environment_key_fails_before_rendering() {
    let redactor = Redactor::default();
    let mut session = redactor.session();
    let _ = session.env(|env| {
        env.redact_pair_as("same", "MODE", "one");
        env.redact_pair_as("same", "MODE", "two");
    });
    assert!(session.finish().is_err());
    assert!(session.finish().unwrap().results().is_empty());
}

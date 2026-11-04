// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public transaction-session tests for environment redaction.

mod env;

#[test]
fn refactor_env_one_pair_matches_batch() {
    use qubit_redact::Redactor;

    let redactor = Redactor::standard();
    let one = redactor.redact_env("PASSWORD", "raw-secret");
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_env("PASSWORD", "raw-secret");
    let out = batch.finish_with_marker("<incomplete>");
    assert_eq!(one.text().as_str(), out.text(handle).as_str());
    assert_eq!(one.summary(), out.summary());
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Regression checks for the transaction runtime ownership boundary.

/// All mutable transaction accounting must be owned by the dedicated runtime
/// state, with final summaries built only at publication time.
#[test]
fn transaction_state_has_one_authoritative_accounting_model() {
    let state = include_str!("../src/runtime/transaction_state.rs");
    let session = include_str!("../src/runtime/redaction_session.rs");
    let writer = include_str!("../src/domain/redaction_writer.rs");
    let writer_definition = writer
        .split("impl<'session> RedactionWriter")
        .next()
        .expect("writer definition precedes its implementation");

    assert!(!state.contains("RedactionSummary"));
    assert!(!session.contains("impl std::ops::Deref for RedactionSession"));
    assert!(!session.contains("impl std::ops::DerefMut for RedactionSession"));
    assert!(state.contains("domain_frame: String"));
    assert!(!writer_definition.contains("output: String"));
    assert!(!writer_definition.contains("output_bytes: usize"));
}

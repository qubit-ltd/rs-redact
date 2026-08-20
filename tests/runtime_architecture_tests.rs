// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression checks for the transaction runtime ownership boundary.

use std::fs;
use std::path::Path;

/// Visits every project-owned Rust source below `directory`.
fn visit_rust_sources(directory: &Path, inspect: &mut impl FnMut(&Path, &str)) {
    for entry in fs::read_dir(directory).expect("the source directory must be readable") {
        let entry = entry.expect("the source directory entry must be readable");
        let path = entry.path();
        if path.is_dir() {
            visit_rust_sources(&path, inspect);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).expect("the Rust source must be readable");
            inspect(&path, &source);
        }
    }
}

/// All mutable transaction accounting must be owned by the dedicated runtime
/// state, with final summaries built only at publication time.
#[test]
fn transaction_state_has_one_authoritative_accounting_model() {
    let state = include_str!("../src/runtime/transaction_state.rs");
    let phase = include_str!("../src/runtime/transaction_phase.rs");
    let session = include_str!("../src/runtime/redaction_session.rs");
    let writer = include_str!("../src/domain/redaction_writer.rs");
    let writer_definition = writer
        .split("impl<'session> RedactionWriter")
        .next()
        .expect("writer definition precedes its implementation");

    assert!(!state.contains("RedactionSummary"));
    assert!(!session.contains("impl std::ops::Deref for RedactionSession"));
    assert!(!session.contains("impl std::ops::DerefMut for RedactionSession"));
    assert!(!session.contains("RedactionOutput::"));
    assert!(!session.contains("RedactedText::from_"));
    assert!(state.contains("output: OutputBuffer"));
    assert!(state.contains("items: Vec<ItemRange>"));
    assert!(state.contains("phase: TransactionPhase"));
    assert!(phase.contains("enum TransactionPhase"));
    assert!(phase.contains("Active"));
    assert!(phase.contains("OutputExhausted"));
    assert!(!state.contains("output_exhausted: bool"));
    assert!(!state.contains("fragments: String"));
    assert!(!state.contains("domain_frame: String"));
    assert!(!state.contains("items: Vec<RedactionOutput>"));
    assert!(!writer_definition.contains("output: String"));
    assert!(!writer_definition.contains("output_bytes: usize"));
}

/// Format adapters must report rendering outcomes to the runtime instead of
/// constructing publishable output, summaries, or safe-text wrappers.
#[test]
fn format_adapters_cannot_construct_published_output_models() {
    let formats = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/formats");
    visit_rust_sources(&formats, &mut |path, source| {
        for forbidden in ["RedactionOutput::", "RedactionSummary::", "RedactedText::from_"] {
            assert!(
                !source.contains(forbidden),
                "{} constructs forbidden runtime output through {forbidden}",
                path.display()
            );
        }
    });
}

/// The structured writer exposes only the scope names fixed by the redesign;
/// Removed aliases must not silently return.
#[test]
fn domain_writer_has_only_the_fixed_root_surface() {
    let writer = include_str!("../src/domain/redaction_writer.rs");
    let root_implementation = writer
        .split("impl<'session> RedactionWriter")
        .nth(1)
        .and_then(|source| source.split("pub struct RedactionFields").next())
        .expect("the root writer implementation must precede its field scope");
    let public_methods = root_implementation
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub fn "))
        .map(|signature| {
            signature
                .split(['(', '<'])
                .next()
                .expect("a public method signature must contain its name")
        })
        .collect::<Vec<_>>();

    assert!(!writer.contains("pub fn list"));
    assert!(!writer.contains("pub fn policy(&self)"));
    assert!(!writer.contains("pub fn unit"));
    assert_eq!(
        public_methods,
        ["literal", "unredacted", "record", "tuple", "sequence", "map", "variant"]
    );
}

/// Field, sequence, and map closures must receive distinct capabilities so a
/// caller cannot accidentally use an operation from the wrong scope.
#[test]
fn domain_writer_capabilities_are_split_by_scope() {
    let writer = include_str!("../src/domain/redaction_writer.rs");
    let fields = writer
        .split("impl<'writer, 'session> RedactionFields")
        .nth(1)
        .and_then(|source| source.split("pub struct RedactionItems").next())
        .expect("the field scope must precede the item scope");
    let items = writer
        .split("impl<'writer, 'session> RedactionItems")
        .nth(1)
        .and_then(|source| source.split("pub struct RedactionEntries").next())
        .expect("the item scope must precede the entry scope");
    let entries = writer
        .split("impl<'writer, 'session> RedactionEntries")
        .nth(1)
        .expect("the entry scope must exist");

    for method in ["unredacted_item", "sensitive_item", "nested_item"] {
        assert!(!fields.contains(&format!("pub fn {method}")));
        assert!(items.contains(&format!("pub fn {method}")));
    }
    for method in ["unredacted_entry", "sensitive_entry", "nested_entry"] {
        assert!(!fields.contains(&format!("pub fn {method}")));
        assert!(entries.contains(&format!("pub fn {method}")));
    }
    for method in [
        "pub fn unredacted<",
        "pub fn sensitive<",
        "pub fn nested<",
        "pub fn map<",
    ] {
        assert!(fields.contains(method));
        assert!(!items.contains(method));
        assert!(!entries.contains(method));
    }
}

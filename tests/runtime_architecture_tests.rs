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

/// Shared accounting must not choose either public publication model.
#[test]
fn runtime_and_buffers_keep_publication_models_separate() {
    let runtime = include_str!("../src/runtime/redaction_runtime.rs");
    let transaction = include_str!("../src/runtime/transaction_state.rs");
    let publication = include_str!("../src/runtime/publication_buffer.rs");
    let text = include_str!("../src/runtime/text_output_buffer.rs");
    let batch = include_str!("../src/runtime/batch_output_buffer.rs");

    assert!(!runtime.contains("aggregate_ranges"));
    assert!(!runtime.contains("items: Vec"));
    assert!(!text.contains("ItemRange"));
    assert!(!batch.contains("aggregate_ranges"));
    assert!(transaction.contains("publication: PublicationBuffer"));
    assert!(!transaction.contains("text: TextOutputBuffer"));
    assert!(!transaction.contains("batch: BatchOutputBuffer"));
    assert!(publication.contains("enum PublicationBuffer"));
}

/// Format adapters must report rendering outcomes to the runtime instead of
/// constructing publishable output, summaries, or safe-text wrappers.
#[test]
fn format_adapters_cannot_construct_published_output_models() {
    let formats = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/formats");
    visit_rust_sources(&formats, &mut |path, source| {
        for forbidden in [
            "RedactionTextOutput::",
            "RedactionSummary::",
            "RedactedText::from_",
        ] {
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
        [
            "literal",
            "unredacted",
            "record",
            "tuple",
            "sequence",
            "map",
            "variant"
        ]
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

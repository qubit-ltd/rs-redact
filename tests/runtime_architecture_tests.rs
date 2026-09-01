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

/// Format adapters must report rendering outcomes to the runtime instead of
/// constructing publishable output, summaries, or safe-text wrappers.
#[test]
fn format_adapters_cannot_construct_published_output_models() {
    let formats = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/formats");
    visit_rust_sources(&formats, &mut |path, source| {
        for forbidden in ["RedactionTextOutput::", "RedactionSummary::", "RedactedText::from_"] {
            assert!(
                !source.contains(forbidden),
                "{} constructs forbidden runtime output through {forbidden}",
                path.display()
            );
        }
    });
}

/// Publication ownership is represented by distinct session types, so the
/// former wrong-mode publication branches cannot return.
#[test]
fn publication_modes_are_owned_by_distinct_session_types() {
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime");
    let module = fs::read_to_string(runtime.join("mod.rs")).expect("the runtime module must be readable");

    for module_name in ["text_session", "batch_session", "inspection_session"] {
        assert!(module.contains(&format!("mod {module_name};")));
    }
    for removed in ["publication_buffer", "redaction_session", "transaction_state"] {
        assert!(!module.contains(&format!("mod {removed};")));
        assert!(!runtime.join(format!("{removed}.rs")).exists());
    }

    visit_rust_sources(&runtime, &mut |path, source| {
        for forbidden in ["PublicationBuffer", "RedactionSession", "TransactionState"] {
            assert!(
                !source.contains(forbidden),
                "{} still depends on removed mode state {forbidden}",
                path.display(),
            );
        }
    });
}

/// Format output limits must be owned by the runtime sink instead of a
/// format-local writer with an independently stored ceiling.
#[test]
fn format_adapters_use_the_runtime_operation_sink() {
    let formats = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/formats");
    visit_rust_sources(&formats, &mut |path, source| {
        assert!(
            !source.contains("RenderedOperation::"),
            "{} constructs a rendered operation outside the runtime sink",
            path.display(),
        );
    });

    for (path, sink) in [
        ("src/runtime/bounded_field_writer.rs", "OperationSink"),
        ("src/formats/uri/internal/bounded_uri_writer.rs", "OperationSink"),
        ("src/formats/http/internal/bounded_log_writer.rs", "OperationSink"),
        ("src/formats/http/internal/bounded_body_writer.rs", "OperationByteSink"),
        ("src/formats/json/bounded_json_redaction.rs", "OperationByteSink"),
    ] {
        let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
            .expect("the bounded writer source must be readable");
        assert!(source.contains(sink), "{path} must delegate its ceiling to {sink}");
    }
}

/// JSON structure admission must build the admitted value during its only
/// parse, then pass that borrowed tree directly to the renderer.
#[test]
fn json_structure_admission_builds_and_reuses_one_admitted_value_tree() {
    let writer = include_str!("../src/formats/json/json_redaction_writer.rs");

    assert_eq!(writer.matches("decode_seed_str").count(), 1);
    assert!(!writer.contains("JsonDeserializer::from_str"));
    assert!(writer.contains("Ok(value) => self.redact_value_direct(&value)"));
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
            "unmarked",
            "record",
            "tuple",
            "transparent",
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
    let fields = include_str!("../src/domain/redaction_fields.rs");
    let items = include_str!("../src/domain/redaction_items.rs");
    let entries = include_str!("../src/domain/redaction_entries.rs");

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

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-time checks for the intentionally narrow public API surface.

use std::env;
use std::fs;
use std::process;
use std::process::Command;
use std::process::Output;

/// Compiles one isolated dependent crate against the current source tree.
fn check_dependent(case: &str, source: &str) -> Output {
    let directory = env::temp_dir().join(format!("qubit-redact-public-api-{}-{case}", process::id()));
    fs::create_dir_all(directory.join("src")).expect("the dependent source directory should be creatable");
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname = \"qubit-redact-public-api-{case}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\nqubit-redact = {{ path = \"{}\", features = [\"json\"] }}\n",
            env!("CARGO_MANIFEST_DIR"),
        ),
    )
    .expect("the dependent manifest should be writable");
    fs::write(directory.join("src/main.rs"), source).expect("the dependent source should be writable");
    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline"])
        .current_dir(&directory)
        .output()
        .expect("cargo check for the dependent crate should run");
    fs::remove_dir_all(directory).expect("the dependent crate should be removable");
    output
}

/// Asserts an intentionally removed API cannot be named by a dependent crate.
fn assert_rejected(case: &str, source: &str, expected_diagnostic: &str) {
    let output = check_dependent(case, source);
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the removed {case} API must not compile",);
    assert!(
        diagnostics.contains(expected_diagnostic),
        "the {case} diagnostics must mention {expected_diagnostic}: {diagnostics}",
    );
}

/// Raw batch publications and their resolution error are internal details.
#[test]
fn test_raw_batch_publication_types_are_not_public() {
    assert_rejected(
        "raw-batch-types",
        concat!(
            "use qubit_",
            "redact::{RedactionBatchHandleError, RedactionBatchOutput};\nfn main() {}\n"
        ),
        "RedactionBatchOutput",
    );
}

/// Inspection methods expose their concrete result instead of a redundant
/// root-level alias.
#[test]
fn test_inspection_result_alias_is_not_public() {
    assert_rejected(
        "inspection-alias",
        concat!("use qubit_", "redact::{RedactionInspectionResult};\nfn main() {}\n"),
        "RedactionInspectionResult",
    );
}

/// Domain writer scope types are reachable only from the domain namespace.
#[test]
fn test_domain_scope_types_are_not_exported_from_the_crate_root() {
    assert_rejected(
        "root-domain-scopes",
        concat!(
            "use qubit_",
            "redact::{RedactionEntries, RedactionFields, RedactionItems};\nfn main() {}\n"
        ),
        "RedactionFields",
    );
}

/// Public batches publish only the fail-closed diagnostics view.
#[test]
fn test_raw_batch_finish_is_not_public() {
    assert_rejected(
        "raw-batch-finish",
        concat!(
            "use qubit_",
            "redact::{Redactor};\nfn main() { let batch = Redactor::strict().batch(); let _ = batch.finish(); }\n"
        ),
        "finish",
    );
}

/// Field scopes cannot invoke sequence-item operations.
#[test]
fn test_field_scope_rejects_item_methods() {
    assert_rejected(
        "field-item-method",
        r#"
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Value;
impl Redact for Value {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Value", |fields| { fields.unredacted_item(|| "value"); });
    }
}
fn main() {}
"#,
        "unredacted_item",
    );
}

/// Field scopes cannot invoke map-entry operations.
#[test]
fn test_field_scope_rejects_entry_methods() {
    assert_rejected(
        "field-entry-method",
        r#"
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Value;
impl Redact for Value {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Value", |fields| { fields.unredacted_entry("key", || "value"); });
    }
}
fn main() {}
"#,
        "unredacted_entry",
    );
}

/// Sequence scopes cannot invoke named-field operations.
#[test]
fn test_item_scope_rejects_field_methods() {
    assert_rejected(
        "item-field-method",
        r#"
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Value;
impl Redact for Value {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.sequence(|items| { items.unredacted("value", || "value"); });
    }
}
fn main() {}
"#,
        "unredacted",
    );
}

/// Sequence scopes cannot invoke map-entry operations.
#[test]
fn test_item_scope_rejects_entry_methods() {
    assert_rejected(
        "item-entry-method",
        r#"
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Value;
impl Redact for Value {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.sequence(|items| { items.unredacted_entry("key", || "value"); });
    }
}
fn main() {}
"#,
        "unredacted_entry",
    );
}

/// Map-entry scopes cannot invoke sequence-item operations.
#[test]
fn test_entry_scope_rejects_item_methods() {
    assert_rejected(
        "entry-item-method",
        r#"
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;
use qubit_redact::Sensitivity;

struct Value;
impl Redact for Value {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.map(|entries| { entries.sensitive_item(Sensitivity::Secret, || "value"); });
    }
}
fn main() {}
"#,
        "sensitive_item",
    );
}

/// Map-entry scopes cannot invoke named-field operations.
#[test]
fn test_entry_scope_rejects_field_methods() {
    assert_rejected(
        "entry-field-method",
        r#"
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Value;
impl Redact for Value {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.map(|entries| { entries.unredacted("value", || "value"); });
    }
}
fn main() {}
"#,
        "unredacted",
    );
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-time checks for the intentionally narrow public API surface.

mod support;

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::process;
use std::process::Output;

use serde_json::Value;
use support::compile_diagnostics::source_error_matches;
use support::manifest::toml_path;

/// Compiles one isolated dependent crate against the current source tree.
///
/// Writes the supplied `source` into an isolated crate for `case`, enables
/// `features` on its runtime dependency, and returns Cargo's JSON output.
/// Blocks on Cargo and removes the temporary crate before returning. Panics if
/// filesystem operations or spawning Cargo fail.
fn check_dependent(case: &str, source: &str, features: &[&str]) -> Output {
    let directory = env::temp_dir().join(format!("qubit-redact-public-api-{}-{case}", process::id()));
    fs::create_dir_all(directory.join("src")).expect("the dependent source directory should be creatable");
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname = \"qubit-redact-public-api-{case}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\nqubit-redact = {{ path = {}, features = {} }}\n",
            toml_path(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))),
            serde_json::to_string(features).expect("feature list serialization"),
        ),
    )
    .expect("the dependent manifest should be writable");
    fs::write(directory.join("src/main.rs"), source).expect("the dependent source should be writable");
    let mut command = support::isolated_cargo::command(OsStr::new(env!("CARGO")));
    command
        .args(["check", "--offline", "--message-format=json"])
        .env("CARGO_NET_OFFLINE", "true")
        .current_dir(&directory);
    let output = command
        .output()
        .expect("cargo check for the dependent crate should run");
    fs::remove_dir_all(directory).expect("the dependent crate should be removable");
    output
}

/// Asserts an intentionally removed API cannot be named by a dependent crate.
fn assert_rejected(case: &str, source: &str, expected_diagnostic: &str) {
    let output = check_dependent(case, source, &["json"]);
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!output.status.success(), "the removed {case} API must not compile",);
    assert!(
        source_error_matches(&output.stdout, expected_diagnostic, None),
        "the {case} diagnostics must mention {expected_diagnostic}: {diagnostics}",
    );
}

/// Returns the fixture's primary rustc error from Cargo's JSON stream.
fn primary_source_diagnostic(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|event| {
            let message = &event["message"];
            let primary = message["spans"]
                .as_array()?
                .iter()
                .find(|span| span["is_primary"] == true)?;
            (event["reason"] == "compiler-message"
                && event["target"]["src_path"]
                    .as_str()
                    .is_some_and(|path| std::path::Path::new(path).ends_with("src/main.rs"))
                && message["level"] == "error")
                .then(|| {
                    format!(
                        "{} {} at src/main.rs:{}",
                        message["code"]["code"].as_str().unwrap_or("<no code>"),
                        message["message"].as_str().unwrap_or("<no message>"),
                        primary["line_start"].as_u64().unwrap_or_default(),
                    )
                })
        })
        .unwrap_or_else(|| "<no fixture-source rustc error>".to_owned())
}

/// Raw batch publications and their resolution error are internal details.
#[test]
fn test_raw_batch_publication_types_are_not_public() {
    assert_rejected(
        "raw-batch-types",
        concat!(
            "use qubit_",
            "redact::{DiagnosticRedactionHandleError, DiagnosticRedactionBatchOutput};\nfn main() {}\n"
        ),
        "DiagnosticRedactionBatchOutput",
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

/// The removed marker-taking method is no longer part of the public API.
#[test]
fn test_legacy_batch_finish_method_is_not_public() {
    assert_rejected(
        "raw-batch-finish",
        concat!(
            "use qubit_",
            "redact::{Redactor};\nfn main() { let batch = Redactor::strict().diagnostic_batch(); let _ = batch.finish_for_diagnostics(\"<incomplete>\"); }\n"
        ),
        "finish_for_diagnostics",
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

/// Scalar derives reject containers regardless of the optional BigDecimal leaf.
#[test]
fn test_scalar_derive_rejects_collection_fields() {
    for features in [&["derive"][..], &["derive", "bigdecimal"][..]] {
        let accepted = check_dependent(
            "scalar-positive",
            concat!(
                "use qubit_",
                "redact::RedactScalar;\n#[derive(RedactScalar)] struct Scalar(u64); fn main() {}"
            ),
            features,
        );
        assert!(
            accepted.status.success(),
            "scalar positive control: {}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        let rejected = check_dependent(
            "scalar-collection",
            concat!(
                "use qubit_",
                "redact::RedactScalar;\n#[derive(RedactScalar)] struct Collection(Vec<u64>); fn main() {}"
            ),
            features,
        );
        assert!(!rejected.status.success(), "collections are not scalar leaves");
        assert!(
            source_error_matches(&rejected.stdout, "Vec<u64>: RedactScalar", Some("E0277")),
            "expected scalar capability rejection: {}\n{}",
            String::from_utf8_lossy(&rejected.stderr),
            String::from_utf8_lossy(&rejected.stdout),
        );
    }
}

/// Checks whether a public derived type can keep a private field type hidden.
#[test]
fn test_private_projection() {
    let source = r#"
use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug)]
struct Private(u8);

#[derive(Redact)]
pub struct Public {
    inner: Private,
}

fn main() {
    let value = Public { inner: Private(7) };
    assert!(Redactor::standard().redact_text(&value).complete_text().is_ok());
}
"#;
    for (feature_name, features) in [
        ("derive", &(["derive"][..])),
        ("derive-serde", &["derive", "serde"][..]),
        ("derive-json", &["derive", "json"][..]),
    ] {
        let output = check_dependent(&format!("private-projection-{feature_name}"), source, features);
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            output.status.success(),
            "private projection must compile for {feature_name} (exit {}): {}\n{diagnostics}",
            output.status,
            primary_source_diagnostic(&output)
        );
        eprintln!(
            "private_projection source=Public{{inner:Private}} features={feature_name} exit={} primary={}",
            output.status,
            primary_source_diagnostic(&output)
        );
    }
}

/// Checks unsized final fields through the text-only derive path.
#[test]
fn test_unsized_projection() {
    let source = r#"
use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Redact)]
pub struct Tail<T: ?Sized> {
    tail: T,
}

pub fn text(value: &Tail<str>) -> String {
    Redactor::standard().redact_text(value).text().as_str().to_owned()
}

pub fn bytes(value: &Tail<[u8]>) -> String {
    Redactor::standard().redact_text(value).text().as_str().to_owned()
}

fn main() {}
"#;
    for (feature_name, features) in [
        ("derive", &(["derive"][..])),
        ("derive-serde", &["derive", "serde"][..]),
        ("derive-json", &["derive", "json"][..]),
    ] {
        let output = check_dependent(&format!("unsized-projection-{feature_name}"), source, features);
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            output.status.success(),
            "unsized projection must compile for {feature_name} (exit {}): {}\n{diagnostics}",
            output.status,
            primary_source_diagnostic(&output)
        );
        eprintln!(
            "unsized_projection source=Tail<str>/Tail<[u8]> features={feature_name} exit={} primary={}",
            output.status,
            primary_source_diagnostic(&output)
        );
    }
}

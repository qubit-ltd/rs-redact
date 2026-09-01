// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-time regression tests for the sealed map field boundary.

use std::env;
use std::fs;
use std::process;
use std::process::Command;

/// Verifies arbitrary pair iterators cannot bypass `RedactMapValue`.
#[test]
fn test_vec_pairs_are_not_accepted_as_redaction_maps() {
    let directory = env::temp_dir().join(format!("qubit-redact-map-api-{}", process::id()));
    fs::create_dir_all(directory.join("src")).expect("temporary dependent crate directory");
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname = \"qubit-redact-map-api\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\nqubit-redact = {{ path = \"{}\" }}\n",
            env!("CARGO_MANIFEST_DIR"),
        ),
    )
    .expect("temporary manifest");
    fs::write(
        directory.join("src/main.rs"),
        r#"
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct PairList {
    values: Vec<(String, String)>,
}

impl Redact for PairList {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("PairList", |fields| {
            fields.map("values", &self.values);
        });
    }
}

fn main() {}
"#,
    )
    .expect("temporary source");

    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline"])
        .current_dir(&directory)
        .output()
        .expect("cargo check for temporary dependent crate");
    let diagnostics = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "Vec pairs must not be a supported map field");
    assert!(
        diagnostics.contains("map"),
        "compiler diagnostics must identify the rejected map call: {diagnostics}",
    );
    fs::remove_dir_all(directory).expect("temporary dependent crate cleanup");
}

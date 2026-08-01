// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for runtime crate-path resolution.
//!
//! Direct source execution covers every Cargo lookup result, while isolated
//! fixtures verify those outcomes through actual proc-macro invocation.

use std::{
    env,
    ffi::OsString,
    path::PathBuf,
    process::Output,
};

use proc_macro_crate::{
    Error,
    FoundCrate,
};
use quote::ToTokens;
use syn::{
    DeriveInput,
    Path,
    parse_quote,
};

#[path = "../../src/internal/crate_path.rs"]
mod crate_path;

/// Creates a minimal input with a stable span for direct crate-path tests.
///
/// # Returns
///
/// A struct derive input that can carry lookup diagnostics.
fn derive_input() -> DeriveInput {
    parse_quote!(
        struct Record;
    )
}

/// Runs Cargo against one isolated runtime-path fixture.
///
/// # Parameters
///
/// * `fixture` - Fixture directory below `tests/fixtures/crates`.
///
/// # Returns
///
/// The complete Cargo output for exact status and diagnostic assertions.
fn check_fixture(fixture: &str) -> Output {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir
        .join("tests/fixtures/crates")
        .join(fixture)
        .join("Cargo.toml");
    let target_dir = manifest_dir
        .join("../target")
        .join(format!("{fixture}-fixture"));
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));

    crate::support::isolated_cargo::command(&cargo)
        .args(["check", "--manifest-path"])
        .arg(manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts")
}

/// Verifies direct resolution preserves self paths and normalizes renamed
/// dependencies for generated absolute paths.
#[test]
fn test_crate_path_resolve_handles_self_and_renamed_dependency() {
    let input = derive_input();
    let itself: Path = parse_quote!(::qubit_redact);
    let self_path = crate_path::resolve(
        &input,
        Ok(FoundCrate::Itself),
        itself.clone(),
        "runtime lookup",
    )
    .expect("self lookup should use the supplied path");
    let renamed_path = crate_path::resolve(
        &input,
        Ok(FoundCrate::Name("redact-runtime".to_owned())),
        itself,
        "runtime lookup",
    )
    .expect("renamed lookup should construct an absolute path");

    assert_eq!(self_path.into_token_stream().to_string(), ":: qubit_redact");
    assert_eq!(
        renamed_path.into_token_stream().to_string(),
        ":: redact_runtime",
    );
}

/// Verifies lookup failures retain the caller-supplied error context.
#[test]
fn test_crate_path_resolve_wraps_lookup_error_with_context() {
    let input = derive_input();
    let itself: Path = parse_quote!(::qubit_redact);
    let error = Error::CrateNotFound {
        crate_name: "qubit-redact".to_owned(),
        path: PathBuf::from("/fixture/Cargo.toml"),
    };
    let result =
        crate_path::resolve(&input, Err(error), itself, "runtime lookup");

    assert!(
        result
            .expect_err("failed lookup should produce a syntax error")
            .to_string()
            .starts_with("runtime lookup:"),
    );
}

/// Verifies generated code resolves a renamed runtime dependency.
#[test]
fn test_runtime_crate_path_resolves_renamed_dependency() {
    let output = check_fixture("renamed_dependency");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
}

/// Verifies a package named `qubit-redact` reaches the `Itself` lookup branch.
#[test]
fn test_runtime_crate_path_resolves_itself() {
    let output = check_fixture("runtime_itself");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("has unknown container attribute"),
        "{stderr}",
    );
    assert!(
        !stderr.contains("unable to resolve the qubit-redact runtime crate"),
        "{stderr}",
    );
}

/// Verifies a missing runtime dependency emits the targeted public diagnostic.
#[test]
fn test_runtime_crate_path_reports_missing_dependency() {
    let output = check_fixture("runtime_missing");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert_eq!(
        stderr
            .matches("unable to resolve the qubit-redact runtime crate")
            .count(),
        2,
        "{stderr}",
    );
}

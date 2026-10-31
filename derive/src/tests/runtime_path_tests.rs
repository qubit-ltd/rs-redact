// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for Cargo runtime-name conversion.

use proc_macro_crate::FoundCrate;
use quote::ToTokens;
use syn::parse_quote;
use syn::DeriveInput;

use crate::runtime_path::internal::resolve;

#[test]
fn test_resolve_names_preserves_aliases_and_escapes_keywords() {
    let input: DeriveInput = parse_quote!(
        struct Record;
    );
    for (name, expected) in [
        ("redaction_runtime", ":: redaction_runtime"),
        ("redaction-runtime", ":: redaction_runtime"),
        ("type", ":: r#type"),
        ("match", ":: r#match"),
        ("gen", ":: r#gen"),
    ] {
        let path = resolve(
            &input,
            Ok(FoundCrate::Name(name.to_owned())),
            parse_quote!(crate),
            "runtime lookup failed",
        )
        .expect("valid dependency name resolves");
        assert!(path.leading_colon.is_some(), "{name}");
        assert_eq!(path.segments.len(), 1, "{name}");
        assert_eq!(path.to_token_stream().to_string(), expected, "{name}");
    }
}

#[test]
fn test_resolve_invalid_name_returns_diagnostic() {
    let input: DeriveInput = parse_quote!(
        struct Record;
    );
    let result = resolve(
        &input,
        Ok(FoundCrate::Name("$invalid".to_owned())),
        parse_quote!(crate),
        "runtime lookup failed",
    );
    let error = match result {
        Ok(_) => panic!("invalid runtime name must be rejected"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "runtime lookup failed: invalid runtime crate name `$invalid`",
    );
}

#[test]
fn test_resolve_itself_retains_supplied_path() {
    let input: DeriveInput = parse_quote!(
        struct Record;
    );
    let path = resolve(
        &input,
        Ok(FoundCrate::Itself),
        parse_quote!(crate),
        "runtime lookup failed",
    )
    .expect("self path resolves");
    assert_eq!(path.to_token_stream().to_string(), "crate");
}

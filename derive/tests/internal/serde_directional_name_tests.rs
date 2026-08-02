// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for directional Serde-name parsing.

use syn::{
    Attribute,
    parse::Parser,
    parse_quote,
};

#[path = "../../src/internal/serde_directional_name.rs"]
mod serde_directional_name;

/// Parses the first rename control from a Serde attribute.
///
/// # Parameters
///
/// * `attribute` - Serde attribute containing one rename control.
///
/// # Returns
///
/// The serialization-side name, or `None` for a deserialize-only control.
///
/// # Errors
///
/// Returns the parser error produced for malformed directional names.
fn parse_rename(attribute: Attribute) -> syn::Result<Option<String>> {
    let mut serialized_name = None;
    attribute.parse_nested_meta(|meta| {
        if meta.path.is_ident("rename") {
            serialized_name =
                serde_directional_name::parse_serialize_name(&meta, "rename")?
                    .map(|literal| literal.value());
        }
        Ok(())
    })?;
    Ok(serialized_name)
}

/// Verifies direct and directional names select the serialization branch.
#[test]
fn test_parse_serialize_name_selects_serialization_branch() {
    let direct = parse_rename(parse_quote!(#[serde(rename = "output")]))
        .expect("direct rename should parse");
    let directional = parse_rename(parse_quote!(
        #[serde(rename(serialize = "output", deserialize = "input"))]
    ))
    .expect("directional rename should parse");

    assert_eq!(direct.as_deref(), Some("output"));
    assert_eq!(directional.as_deref(), Some("output"));
}

/// Verifies deserialize-only names leave serialization unchanged.
#[test]
fn test_parse_serialize_name_ignores_deserialize_only_branch() {
    let serialized_name = parse_rename(parse_quote!(
        #[serde(rename(deserialize = "input"))]
    ))
    .expect("deserialize-only rename should parse");

    assert_eq!(serialized_name, None);
}

/// Verifies malformed directional controls return targeted diagnostics.
#[test]
fn test_parse_serialize_name_rejects_invalid_directional_controls() {
    let invalid: [Attribute; 4] = [
        parse_quote!(#[serde(rename())]),
        parse_quote!(#[serde(rename(serialize = "a", serialize = "b"))]),
        parse_quote!(#[serde(rename(deserialize = "a", deserialize = "b"))]),
        parse_quote!(#[serde(rename(other = "value"))]),
    ];

    for attribute in invalid {
        assert!(
            parse_rename(attribute).is_err(),
            "invalid directional control should fail"
        );
    }

    let mut serialized_name = None;
    let parser = syn::meta::parser(|meta| {
        serialized_name =
            serde_directional_name::parse_serialize_name(&meta, "rename")?;
        Ok(())
    });
    let error = parser
        .parse_str("rename")
        .expect_err("a bare rename control should fail")
        .to_string();
    assert!(error.contains("expects"), "unexpected diagnostic: {error}");
}

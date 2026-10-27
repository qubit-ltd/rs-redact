// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for generated derive implementations.

use quote::ToTokens;
use syn::DeriveInput;
use syn::Generics;
use syn::Path;
use syn::Type;
use syn::parse_quote;

use crate::expand;
use crate::expand::assertions;

#[test]
fn test_expansion_generates_only_the_requested_public_contracts() {
    let input: DeriveInput = parse_quote! {
        #[redact(crate = crate, debug, display)]
        struct Record {
            #[redact(level = "secret")]
            value: String,
        }
    };

    let rendered = expand::expand(&input).expect("valid input expands").to_string();
    for expected in ["Redact", "Debug", "Display"] {
        assert!(rendered.contains(expected), "missing {expected}: {rendered}");
    }
    for removed in ["RedactMut", "redacted_with", "expand_with_options"] {
        assert!(
            !rendered.contains(removed),
            "retained removed contract {removed}: {rendered}"
        );
    }
}

#[test]
fn test_adapter_generics_keep_path_and_transitive_bounds_only() {
    let input: DeriveInput = parse_quote! {
        struct Record<'a, T, U, const N: usize, V>
        where
            T: Into<U>,
            U: Copy,
            T: 'a,
        {
            value: u32,
        }
    };
    let generics: Generics = input.generics;
    let field_type: Type = parse_quote!(u32);
    let adapter: Path = parse_quote!(encode::<T, N>);

    let selected = assertions::generics_for_field_and_adapter(&generics, &field_type, &adapter);
    let parameters: Vec<String> = selected
        .params
        .iter()
        .map(ToTokens::to_token_stream)
        .map(|tokens| tokens.to_string())
        .collect();

    assert_eq!(parameters, ["'a", "T", "U", "const N : usize"].map(str::to_owned));
    let predicates = selected
        .where_clause
        .expect("transitively related predicates are retained")
        .predicates;
    assert_eq!(predicates.len(), 3);
    let rendered = predicates.to_token_stream().to_string();
    for expected in ["T : Into < U >", "U : Copy", "T : 'a"] {
        assert!(rendered.contains(expected), "missing `{expected}` in `{rendered}`");
    }
}

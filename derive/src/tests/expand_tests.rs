// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for generated derive implementations.

use syn::DeriveInput;
use syn::parse_quote;

use crate::expand;

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

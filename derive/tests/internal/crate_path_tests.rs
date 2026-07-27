// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for shared Cargo crate-path mapping.

use std::path::PathBuf;

use proc_macro_crate::{
    Error,
    FoundCrate,
};
use quote::ToTokens;
use syn::{
    DeriveInput,
    Path,
};

/// Production crate-path mapper compiled into this black-box test.
mod crate_path {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/internal/crate_path.rs"
    ));
}

/// Verifies every Cargo lookup outcome maps to a stable path or diagnostic.
#[test]
fn test_resolve_maps_every_lookup_outcome() {
    let input: DeriveInput = syn::parse_quote!(
        struct Record;
    );
    let itself_path: Path = syn::parse_quote!(::qubit_redact);

    let itself = crate_path::resolve(
        &input,
        Ok(FoundCrate::Itself),
        itself_path.clone(),
        "unable to resolve runtime",
    )
    .expect("the current crate uses its canonical path");
    let renamed = crate_path::resolve(
        &input,
        Ok(FoundCrate::Name("safe-log".into())),
        itself_path.clone(),
        "unable to resolve runtime",
    )
    .expect("renamed dependencies are supported");
    let missing = crate_path::resolve(
        &input,
        Err(Error::CrateNotFound {
            crate_name: "qubit-redact".to_owned(),
            path: PathBuf::from("/workspace/Cargo.toml"),
        }),
        itself_path,
        "unable to resolve runtime",
    )
    .expect_err("a missing dependency is rejected");

    assert_eq!(itself.to_token_stream().to_string(), ":: qubit_redact");
    assert_eq!(renamed.to_token_stream().to_string(), ":: safe_log");
    assert_eq!(
        missing.to_string(),
        "unable to resolve runtime: Could not find `qubit-redact` in \
         `dependencies` or `dev-dependencies` in `/workspace/Cargo.toml`!",
    );
}

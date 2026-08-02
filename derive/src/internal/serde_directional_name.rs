// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict parsing for Serde serialization/deserialization name pairs.

use syn::{
    LitStr,
    Token,
    meta::ParseNestedMeta,
};

/// Parses a Serde name in string or directional list form.
///
/// The returned literal is only the `serialize` branch. A deserialize-only
/// declaration returns `None`, allowing generated serialization to retain its
/// default name while the caller separately records that the control occurred.
pub(crate) fn parse_serialize_name(
    meta: &ParseNestedMeta<'_>,
    control: &str,
) -> syn::Result<Option<LitStr>> {
    if meta.input.peek(Token![=]) {
        return Ok(Some(meta.value()?.parse()?));
    }
    if !meta.input.peek(syn::token::Paren) {
        return Err(meta.error(format!(
            "Redact serde expects `{control} = \"...\"` or `{control}(serialize = \"...\", deserialize = \"...\")`",
        )));
    }

    let mut serialize = None;
    let mut deserialize_seen = false;
    let mut item_seen = false;
    meta.parse_nested_meta(|direction| {
        item_seen = true;
        if direction.path.is_ident("serialize") {
            if serialize.is_some() {
                return Err(direction.error(format!(
                    "Redact serde `{control}` repeats `serialize`",
                )));
            }
            serialize = Some(direction.value()?.parse()?);
        } else if direction.path.is_ident("deserialize") {
            if deserialize_seen {
                return Err(direction.error(format!(
                    "Redact serde `{control}` repeats `deserialize`",
                )));
            }
            let _: LitStr = direction.value()?.parse()?;
            deserialize_seen = true;
        } else {
            return Err(direction.error(format!(
                "Redact serde `{control}` supports only `serialize` and `deserialize`",
            )));
        }
        Ok(())
    })?;
    if !item_seen {
        return Err(meta.error(format!(
            "Redact serde `{control}` requires `serialize` or `deserialize`",
        )));
    }
    Ok(serialize)
}

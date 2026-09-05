// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict parsing for Serde serialization/deserialization name pairs.

use syn::LitStr;
use syn::Result;
use syn::Token;
use syn::meta::ParseNestedMeta;
use syn::token::Paren;

/// Parses a Serde name in string or directional list form.
///
/// The returned literal is only the `serialize` branch. A deserialize-only
/// declaration returns `None`, allowing generated serialization to retain its
/// default name while the caller separately records that the control occurred.
///
/// # Parameters
///
/// * `meta` - Nested Serde metadata item containing a direct or directional
///   name.
/// * `control` - Attribute control name used in targeted diagnostics.
///
/// # Returns
///
/// The serialize-side name literal, or `None` when only a deserialize-side
/// name was provided.
///
/// # Errors
///
/// Returns an error when the value is not a string, the directional form is
/// empty, a direction is repeated, or an unsupported direction is supplied.
pub(crate) fn parse_serialize_name(meta: &ParseNestedMeta<'_>, control: &str) -> Result<Option<LitStr>> {
    if meta.input.peek(Token![=]) {
        return Ok(Some(meta.value()?.parse()?));
    }
    if !meta.input.peek(Paren) {
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
                return Err(direction.error(format!("Redact serde `{control}` repeats `serialize`",)));
            }
            serialize = Some(direction.value()?.parse()?);
        } else if direction.path.is_ident("deserialize") {
            if deserialize_seen {
                return Err(direction.error(format!("Redact serde `{control}` repeats `deserialize`",)));
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

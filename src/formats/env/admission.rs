// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared environment-name admission.

use std::ffi::OsStr;

use crate::runtime::runtime_session::RuntimeSession;

/// Checks a Unicode environment name against the classification-key limit.
///
/// Non-Unicode names retain the renderer's existing conservative secret
/// handling because they have no UTF-8 key representation to measure.
pub(in crate::formats) fn admit_environment_name(session: &mut dyn RuntimeSession, name: &OsStr) -> bool {
    match name.to_str() {
        Some(name) => session.admit_domain_key(name),
        None => true,
    }
}

/// Collects environment pairs incrementally, stopping before reading past a
/// rejected classification name.
///
/// # Parameters
///
/// - `session`: Shared transaction that accounts for structure, keys, and input
///   bytes.
/// - `pairs`: Borrowed environment pairs consumed in source order.
///
/// # Returns
///
/// `Some` contains all admitted pairs. `None` means a structural, key, or
/// input-byte limit rejected an item, which is not included in the result.
pub(in crate::formats) fn collect_environment_pairs<'items, I>(
    session: &mut dyn RuntimeSession,
    pairs: I,
) -> Option<Vec<(&'items OsStr, &'items OsStr)>>
where
    I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
{
    if !session.admit_format_node(1) {
        return None;
    }
    let mut pairs = pairs.into_iter();
    let mut admitted = Vec::new();
    loop {
        if pairs.size_hint().1 == Some(0) {
            break;
        }
        if !session.preflight_format_item(2) {
            return None;
        }
        let Some((name, value)) = pairs.next() else {
            break;
        };
        if !session.admit_format_collection_item()
            || !session.admit_format_node(2)
            || !admit_environment_name(session, name)
            || !session.admit_input(
                name.as_encoded_bytes()
                    .len()
                    .saturating_add(value.as_encoded_bytes().len()),
            )
        {
            return None;
        }
        admitted.push((name, value));
    }
    Some(admitted)
}

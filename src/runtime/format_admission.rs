// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared admission for flat structured format inputs.

use super::runtime_session::RuntimeSession;

/// Admits one item represented as a root node containing one child value.
///
/// The input length is charged only after all structural limits admit the
/// item. A rejected item must not be rendered by the caller.
#[must_use]
pub(crate) fn admit_flat_format_item<S>(session: &mut S, input_bytes: usize) -> bool
where
    S: RuntimeSession,
{
    session.admit_format_node(1)
        && session.admit_format_collection_item()
        && session.admit_format_node(2)
        && session.admit_input(input_bytes)
}

/// Collects a flat structured input while the shared transaction admits it.
///
/// The iterator is advanced only after structural capacity has been checked.
/// This prevents a rejected suffix from triggering caller-controlled iterator
/// work, allocation, or value access.
#[must_use]
pub(crate) fn collect_flat_format_items<S, I, F>(session: &mut S, items: I, mut input_bytes: F) -> Option<Vec<I::Item>>
where
    S: RuntimeSession,
    I: IntoIterator,
    F: FnMut(&I::Item) -> usize,
{
    if !session.admit_format_node(1) {
        return None;
    }
    let mut iterator = items.into_iter();
    let mut admitted = Vec::new();
    loop {
        if iterator.size_hint().1 == Some(0) {
            break;
        }
        if !session.preflight_format_item(2) {
            return None;
        }
        let Some(item) = iterator.next() else {
            break;
        };
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return None;
        }
        if !session.admit_input(input_bytes(&item)) {
            return None;
        }
        admitted.push(item);
    }
    Some(admitted)
}

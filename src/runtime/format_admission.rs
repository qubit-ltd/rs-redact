// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared admission for flat structured format inputs.

use super::runtime_session::RuntimeSession;

/// Collects a flat structured input while the shared transaction admits it.
///
/// The iterator is advanced only after structural capacity has been checked.
/// This prevents a rejected suffix from triggering caller-controlled iterator
/// work, allocation, or value access.
///
/// # Type Parameters
///
/// - `S`: Session type that provides shared format and input accounting.
/// - `I`: Iterable source of flat input values.
/// - `F`: Function that computes each item's charged input byte cost.
///
/// # Parameters
///
/// - `session`: Shared transaction accounting state to update.
/// - `items`: Flat input values to admit before the caller renders them.
/// - `input_bytes`: Returns the byte cost charged for each admitted value.
///
/// # Returns
///
/// `Some` contains every admitted item when the input fits. `None` means a
/// structural or byte limit rejected the input; the rejecting item is not
/// returned, and the iterator is not advanced past the rejected capacity.
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

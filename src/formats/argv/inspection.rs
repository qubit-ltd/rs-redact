// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering sensitivity inspection for process argument vectors.

use super::ArgvItem;
use super::pending_field::PendingField;
use super::redaction::inspect_heuristic_item;
use crate::runtime::InspectionSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Inspects an argv source under the transaction's shared structural budget.
pub(crate) fn inspect_items<'items, I>(session: &mut InspectionSession, items: I, heuristic: bool)
where
    I: IntoIterator<Item = ArgvItem<'items>>,
{
    if !session.admit_format_node(1) {
        return;
    }
    let policy = session.policy().clone();
    let mut pending = None::<PendingField>;
    let mut items = items.into_iter();
    loop {
        if items.size_hint().1 == Some(0) {
            break;
        }
        if !session.preflight_format_item(2) {
            return;
        }
        let Some(item) = items.next() else {
            break;
        };
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return;
        }
        if !session.admit_input(item.value().as_encoded_bytes().len()) {
            return;
        }
        let sensitivity = if heuristic {
            inspect_heuristic_item(&policy, item, &mut pending)
        } else {
            item.sensitivity()
        };
        if let Some(sensitivity) = sensitivity {
            session.observe_sensitivity(sensitivity);
        }
    }
}

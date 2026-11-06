// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Accounts JSON tree visits against shared transaction ledgers.

use qubit_json::value::traverse::JsonTreeContext;
use qubit_json::value::traverse::JsonTreeLocation;
use qubit_json::value::traverse::JsonTreeVisitor;
use serde_json::Value;

use crate::RedactionReason;
use crate::RedactionUsage;
use crate::runtime::StructuralBudget;
use crate::runtime::structural_entry::StructuralEntry;

/// Admits parsed JSON values into the transaction's shared structural ledger.
///
/// The visitor mutably borrows the transaction's structural budget, cumulative
/// usage, and optional per-operation usage as disjoint fields. `base_depth`
/// offsets each JSON-relative context depth by the domain depth active when
/// admission began. The root contributes a structural node only; every
/// non-root value contributes a collection item before its node is admitted.
/// Consequently, a node rejection can leave an already-counted collection
/// item, and counts from earlier successful visits, in the usage ledgers.
///
/// # Type Parameters
///
/// - `'a`: Exclusive borrow shared by the transaction ledgers during admission.
pub(in crate::runtime::redaction_budget) struct JsonUsageVisitor<'a> {
    /// Shared domain and format traversal limits.
    pub(in crate::runtime::redaction_budget) structural: &'a mut StructuralBudget,
    /// Cumulative resource use for the entire transaction.
    pub(in crate::runtime::redaction_budget) usage: &'a mut RedactionUsage,
    /// Resource use for the active independently published item, if any.
    pub(in crate::runtime::redaction_budget) active_operation_usage: &'a mut Option<RedactionUsage>,
    /// Domain depth at which this JSON tree was admitted.
    pub(in crate::runtime::redaction_budget) base_depth: usize,
}

impl JsonTreeVisitor for JsonUsageVisitor<'_> {
    /// Structural rejection that stops JSON admission.
    type Error = RedactionReason;

    /// Accounts a collection item (except for the root) before admitting its
    /// root-inclusive absolute depth as a structural node.
    ///
    /// Returns `DepthLimitReached` when the depth limit rejects the node and
    /// `TraversalLimitReached` when its collection-item or node limit rejects
    /// it. The first reached rejection is returned and stops this traversal.
    /// The visitor does not roll back an item already counted before a later
    /// depth/node rejection, or visits completed before an error.
    ///
    /// # Parameters
    ///
    /// - `_value`: Admitted JSON node; its contents are not needed for
    ///   accounting.
    /// - `context`: Root-relative location and depth supplied by the reader.
    ///
    /// # Returns
    ///
    /// `Ok(())` after charging the item and node.
    ///
    /// # Errors
    ///
    /// Returns the first depth, collection-item, or node-limit rejection.
    fn enter(&mut self, _value: &Value, context: JsonTreeContext<'_>) -> Result<(), Self::Error> {
        if !matches!(context.location, JsonTreeLocation::Root) {
            if !self.structural.admit_collection_item() {
                return Err(RedactionReason::TraversalLimitReached);
            }
            *self.usage = self.usage.with_collection_item();
            if let Some(usage) = self.active_operation_usage.as_mut() {
                *usage = usage.with_collection_item();
            }
        }
        let depth = self.base_depth.saturating_add(context.depth);
        match self.structural.admit_format_node(depth) {
            StructuralEntry::Entered => {}
            StructuralEntry::DepthLimitReached => return Err(RedactionReason::DepthLimitReached),
            StructuralEntry::TraversalLimitReached => {
                return Err(RedactionReason::TraversalLimitReached);
            }
        }
        *self.usage = self.usage.with_domain_node(depth);
        if let Some(usage) = self.active_operation_usage.as_mut() {
            *usage = usage.with_domain_node(depth);
        }
        Ok(())
    }
}

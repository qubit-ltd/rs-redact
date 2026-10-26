// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable limits owned by one active redaction transaction.

#[cfg(feature = "json")]
use qubit_budget::json::JsonValueBudget;
#[cfg(feature = "json")]
use qubit_json::value::traverse::JsonTreeContext;
#[cfg(feature = "json")]
use qubit_json::value::traverse::JsonTreeLocation;
#[cfg(feature = "json")]
use qubit_json::value::traverse::JsonTreeReader;
#[cfg(feature = "json")]
use qubit_json::value::traverse::JsonTreeVisitor;
#[cfg(feature = "json")]
use serde_json::Value;

use super::StructuralBudget;
#[cfg(feature = "json")]
use super::structural_entry::StructuralEntry;
use crate::RedactionLimits;
#[cfg(feature = "json")]
use crate::RedactionReason;
use crate::RedactionUsage;

/// The single mutable budget ledger for an active transaction.
pub(super) struct RedactionBudget {
    /// Transaction-wide ceiling for retained safe output.
    output_limit: usize,
    /// Shared structural ledger used across domain and format traversal.
    structural: StructuralBudget,
    /// Cumulative transaction resource measurements.
    usage: RedactionUsage,
    /// Resource delta for the active independently published item.
    active_operation_usage: Option<RedactionUsage>,
    /// JSON-specific ledger for tree and payload limits.
    #[cfg(feature = "json")]
    json_budget: JsonValueBudget,
}

/// Disjoint budget fields borrowed during one JSON text admission.
///
/// # Type Parameters
///
/// - `'budget`: Exclusive borrow of the transaction budget being split.
#[cfg(feature = "json")]
pub(super) type JsonAdmissionBudgetParts<'budget> = (
    &'budget mut StructuralBudget,
    &'budget mut RedactionUsage,
    &'budget mut Option<RedactionUsage>,
    &'budget mut JsonValueBudget,
);

impl RedactionBudget {
    /// Creates the budget from the immutable policy limits.
    ///
    /// # Parameters
    ///
    /// - `limits`: Immutable policy limits copied into the new ledger.
    ///
    /// # Returns
    ///
    /// A fresh ledger with no active per-item accounting.
    #[must_use]
    #[inline(always)]
    pub(super) fn new(limits: &RedactionLimits) -> Self {
        Self {
            output_limit: limits.max_output_bytes(),
            structural: StructuralBudget::new(limits.structural_limits()),
            usage: RedactionUsage::empty(),
            active_operation_usage: None,
            #[cfg(feature = "json")]
            json_budget: limits.json_limits().budget(),
        }
    }

    /// Returns the transaction-wide output ceiling.
    ///
    /// # Returns
    ///
    /// The maximum retained safe output bytes for this transaction.
    #[must_use]
    #[inline(always)]
    pub(super) const fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Returns cumulative resource use for the active transaction.
    ///
    /// # Returns
    ///
    /// The cumulative resource snapshot for the entire transaction.
    #[must_use]
    #[inline(always)]
    pub(super) const fn usage(&self) -> RedactionUsage {
        self.usage
    }

    /// Returns the active operation's resource snapshot.
    ///
    /// # Returns
    ///
    /// `Some(usage)` measures the current item; `None` means no item scope
    /// owns separate accounting.
    #[must_use]
    #[inline(always)]
    pub(super) const fn active_operation_usage(&self) -> Option<RedactionUsage> {
        self.active_operation_usage
    }

    /// Borrows the structural budget for one admission decision.
    ///
    /// # Returns
    ///
    /// An exclusive borrow of the shared structural ledger.
    #[inline(always)]
    #[must_use]
    pub(super) fn structural(&mut self) -> &mut StructuralBudget {
        &mut self.structural
    }

    /// Splits structural accounting from lexical JSON value accounting.
    ///
    /// # Returns
    ///
    /// Disjoint borrows of structural state, total usage, optional item usage,
    /// and JSON value budget, in that order. The item slot is `None` outside an
    /// item.
    #[cfg(feature = "json")]
    #[inline(always)]
    #[must_use]
    pub(super) fn split_json_admission(&mut self) -> JsonAdmissionBudgetParts<'_> {
        (
            &mut self.structural,
            &mut self.usage,
            &mut self.active_operation_usage,
            &mut self.json_budget,
        )
    }

    /// Starts resource accounting for one individually published operation.
    ///
    /// # Returns
    ///
    /// `true` when a new item scope was created; `false` when an outer item
    /// already owns the scope and must retain ownership.
    #[must_use]
    #[inline]
    pub(super) fn begin_operation_usage(&mut self) -> bool {
        if self.active_operation_usage.is_some() {
            return false;
        }
        self.active_operation_usage = Some(RedactionUsage::empty());
        true
    }

    /// Ends resource accounting for an individually published operation.
    ///
    /// # Parameters
    ///
    /// - `owns_operation`: Whether this caller created the active item scope.
    #[inline]
    pub(super) fn end_operation_usage(&mut self, owns_operation: bool) {
        if owns_operation {
            self.active_operation_usage = None;
        }
    }

    /// Records retained safe output bytes.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Newly retained final output bytes to charge.
    #[inline]
    pub(super) fn record_output_bytes(&mut self, bytes: usize) {
        self.usage = self.usage.with_added_output_bytes(bytes);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_added_output_bytes(bytes));
        }
    }

    /// Records ordinary presented and inspected input bytes.
    ///
    /// # Parameters
    ///
    /// - `presented`: Submitted raw bytes, including rejected units.
    /// - `inspected`: Admitted raw bytes actually inspected by this operation.
    #[inline]
    pub(super) fn record_input(&mut self, presented: usize, inspected: usize) {
        self.usage = self.usage.with_input(presented, inspected);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_input(presented, inspected));
        }
    }

    /// Records source-aware input accounting.
    ///
    /// # Parameters
    ///
    /// - `presented`: Available original source length or captured length.
    /// - `inspected`: Admitted captured bytes.
    /// - `omitted`: `Some(bytes)` measures known omitted source bytes; `None`
    ///   means unknown.
    #[cfg(feature = "http")]
    #[inline]
    pub(super) fn record_source_input(&mut self, presented: usize, inspected: usize, omitted: Option<usize>) {
        self.usage = self.usage.with_source_input(presented, inspected, omitted);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_source_input(presented, inspected, omitted));
        }
    }

    /// Records one admitted structural node.
    ///
    /// # Parameters
    ///
    /// - `depth`: Root-inclusive depth of the admitted node.
    #[inline]
    pub(super) fn record_structural_node(&mut self, depth: usize) {
        self.usage = self.usage.with_domain_node(depth);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_domain_node(depth));
        }
    }

    /// Records one admitted collection item.
    #[inline]
    pub(super) fn record_collection_item(&mut self) {
        self.usage = self.usage.with_collection_item();
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_collection_item());
        }
    }

    /// Admits an entire parsed JSON tree atomically against JSON limits.
    ///
    /// # Parameters
    ///
    /// - `root`: Borrowed JSON tree to account before rendering.
    ///
    /// # Returns
    ///
    /// Whether complete tree accounting and its budget transaction both
    /// succeeded.
    #[cfg(feature = "json")]
    #[inline]
    pub(super) fn admit_json_value(&mut self, root: &Value) -> Result<(), RedactionReason> {
        let Self {
            structural,
            usage,
            active_operation_usage,
            json_budget,
            ..
        } = self;
        let mut visitor = JsonUsageVisitor {
            structural,
            usage,
            active_operation_usage,
        };
        let mut transaction = json_budget.transaction();
        let admitted = JsonTreeReader::new(&mut transaction).process(root, &mut visitor);
        let committed = transaction.commit().is_ok();
        match admitted {
            Ok(()) if committed => Ok(()),
            Ok(()) | Err(qubit_json::value::traverse::JsonTreeProcessError::Budget(_)) => {
                Err(RedactionReason::TraversalLimitReached)
            }
            Err(qubit_json::value::traverse::JsonTreeProcessError::Visitor(reason)) => Err(reason),
        }
    }
}

#[cfg(feature = "json")]
struct JsonUsageVisitor<'a> {
    structural: &'a mut StructuralBudget,
    usage: &'a mut RedactionUsage,
    active_operation_usage: &'a mut Option<RedactionUsage>,
}

#[cfg(feature = "json")]
impl JsonTreeVisitor for JsonUsageVisitor<'_> {
    type Error = RedactionReason;

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
        match self.structural.admit_format_node(context.depth) {
            StructuralEntry::Entered => {}
            StructuralEntry::DepthLimitReached => return Err(RedactionReason::DepthLimitReached),
            StructuralEntry::TraversalLimitReached => return Err(RedactionReason::TraversalLimitReached),
        }
        *self.usage = self.usage.with_domain_node(context.depth);
        if let Some(usage) = self.active_operation_usage.as_mut() {
            *usage = usage.with_domain_node(context.depth);
        }
        Ok(())
    }
}

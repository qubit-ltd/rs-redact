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
use qubit_json::value::traverse::JsonTreeReader;
#[cfg(feature = "json")]
use serde_json::Value;

use super::StructuralBudget;
use crate::RedactionLimits;
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

impl RedactionBudget {
    /// Creates the budget from the immutable policy limits.
    #[must_use]
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
    #[must_use]
    pub(super) const fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Returns cumulative resource use for the active transaction.
    #[must_use]
    pub(super) const fn usage(&self) -> RedactionUsage {
        self.usage
    }

    /// Starts resource accounting for one individually published operation.
    pub(super) fn begin_operation_usage(&mut self) -> bool {
        if self.active_operation_usage.is_some() {
            return false;
        }
        self.active_operation_usage = Some(RedactionUsage::empty());
        true
    }

    /// Returns the active operation's resource snapshot.
    #[must_use]
    pub(super) const fn active_operation_usage(&self) -> Option<RedactionUsage> {
        self.active_operation_usage
    }

    /// Ends resource accounting for an individually published operation.
    pub(super) fn end_operation_usage(&mut self, owns_operation: bool) {
        if owns_operation {
            self.active_operation_usage = None;
        }
    }

    /// Records retained safe output bytes.
    pub(super) fn record_output_bytes(&mut self, bytes: usize) {
        self.usage = self.usage.with_added_output_bytes(bytes);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_added_output_bytes(bytes));
        }
    }

    /// Records ordinary presented and inspected input bytes.
    pub(super) fn record_input(&mut self, presented: usize, inspected: usize) {
        self.usage = self.usage.with_input(presented, inspected);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_input(presented, inspected));
        }
    }

    /// Records source-aware input accounting.
    #[cfg(feature = "http")]
    pub(super) fn record_source_input(&mut self, presented: usize, inspected: usize, omitted: Option<usize>) {
        self.usage = self.usage.with_source_input(presented, inspected, omitted);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_source_input(presented, inspected, omitted));
        }
    }

    /// Records one admitted structural node.
    pub(super) fn record_structural_node(&mut self, depth: usize) {
        self.usage = self.usage.with_domain_node(depth);
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_domain_node(depth));
        }
    }

    /// Records one admitted collection item.
    pub(super) fn record_collection_item(&mut self) {
        self.usage = self.usage.with_collection_item();
        if let Some(usage) = self.active_operation_usage {
            self.active_operation_usage = Some(usage.with_collection_item());
        }
    }

    /// Borrows the structural budget for one admission decision.
    pub(super) fn structural(&mut self) -> &mut StructuralBudget {
        &mut self.structural
    }

    /// Admits an entire parsed JSON tree atomically against JSON limits.
    #[cfg(feature = "json")]
    pub(super) fn admit_json_value(&mut self, root: &Value) -> bool {
        let mut transaction = self.json_budget.transaction();
        if JsonTreeReader::new(&mut transaction).account(root).is_err() {
            return false;
        }
        transaction.commit();
        true
    }

    /// Borrows the transaction-wide JSON value budget for decoder admission.
    #[cfg(feature = "json")]
    pub(super) fn json_value_budget_mut(&mut self) -> &mut JsonValueBudget {
        &mut self.json_budget
    }
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable counters for one structured Serde budget scope.

#[cfg(feature = "json")]
use std::cell::RefCell;
#[cfg(feature = "json")]
use std::rc::Rc;

#[cfg(feature = "json")]
use crate::RedactionReason;
#[cfg(feature = "json")]
use crate::RedactionReasons;

/// Per-call event sink registered with an active structured ledger.
#[cfg(feature = "json")]
#[derive(Default)]
pub(super) struct StructuredSerdeReport {
    pub(super) reasons: RedactionReasons,
}

/// Tracks structural, source, and logical payload counters for one nested Serde
/// scope.
pub(super) struct StructuredSerdeBudget {
    /// Address identity of the owned policy snapshot that owns this budget.
    ///
    /// An active policy frame keeps the snapshot alive; the identity is used
    /// only for comparison and is never dereferenced.
    pub(super) policy_identity: usize,
    /// Limits copied from the active redaction policy.
    pub(super) policy: crate::policy::RedactionLimits,
    /// Active ordinary serializers pinning this budget across nested policies.
    pub(super) raw_serializers: usize,
    /// Current structured traversal depth.
    pub(super) depth: usize,
    /// Structural nodes admitted so far.
    pub(super) nodes: usize,
    /// Collection items admitted so far.
    pub(super) collection_items: usize,
    /// Input bytes admitted so far.
    pub(super) input_bytes: usize,
    /// Scalar payload bytes passed to the downstream serializer.
    pub(super) payload_bytes: usize,
    /// Active downstream forwarding of a scalar already charged by its owner.
    pub(super) payload_forwarding: usize,
    /// Optional observers for calls currently active on this ledger.
    #[cfg(feature = "json")]
    pub(super) reports: Vec<Rc<RefCell<StructuredSerdeReport>>>,
}

#[cfg(feature = "json")]
impl StructuredSerdeBudget {
    pub(super) fn record(&mut self, reason: RedactionReason) {
        for report in &self.reports {
            let mut report = report.borrow_mut();
            report.reasons = report.reasons.with(reason);
        }
    }
}

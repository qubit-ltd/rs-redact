// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable counters for one structured Serde budget scope.

/// Tracks structural and input counters for one nested Serde scope.
pub(super) struct StructuredSerdeBudget {
    /// Address identity of the policy reference that owns this budget.
    ///
    /// The address is used only while the scope guard keeps that reference
    /// borrowed and is never dereferenced.
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
    pub(super) output_bytes: usize,
}

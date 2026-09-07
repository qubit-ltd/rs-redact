// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable counters for one structured Serde budget scope.

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
}

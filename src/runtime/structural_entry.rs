// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Result of a transaction-owned structural admission.

/// Result of admitting one structural node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuralEntry {
    /// The node is admitted.
    Entered,
    /// The configured nesting depth rejects the node.
    DepthLimitReached,
    /// The shared node or collection traversal budget rejects the node.
    TraversalLimitReached,
}

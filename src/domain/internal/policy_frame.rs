// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Owned policy snapshots held by thread-local serialization scopes.

use std::sync::Arc;

/// Keeps identity lookup independent of the original policy's storage lifetime.
pub(super) struct PolicyFrame {
    /// Original policy address used only as a snapshot-reuse hint.
    /// It is never dereferenced, and matching addresses also require equal
    /// policy contents because a forgotten guard can outlive that source.
    pub(super) source_identity: usize,
    /// Owned immutable policy used throughout the active serialization scope.
    pub(super) snapshot: Arc<crate::RedactionPolicy>,
}

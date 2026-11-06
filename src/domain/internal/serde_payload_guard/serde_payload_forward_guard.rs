// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Scoped forwarding of an already admitted Serde payload.

use super::super::redact_serialize_scope::begin_payload_forwarding;
use super::super::redact_serialize_scope::end_payload_forwarding;

/// Marks the synchronous downstream forwarding of one already charged string.
pub(in crate::domain::internal) struct SerdePayloadForwardGuard {
    /// Whether construction entered a forwarding scope that must be left.
    active: bool,
}

impl SerdePayloadForwardGuard {
    /// Starts forwarding within the active structured budget, if present.
    ///
    /// # Returns
    ///
    /// A guard that restores the matching scope state when dropped.
    #[must_use]
    #[inline]
    pub(in crate::domain::internal) fn new() -> Self {
        Self {
            active: begin_payload_forwarding(),
        }
    }
}

impl Drop for SerdePayloadForwardGuard {
    /// Leaves the forwarding scope only when this guard entered one.
    ///
    /// This runs on normal return and panic unwinding, but not on abort or if
    /// the guard is leaked.
    #[inline]
    fn drop(&mut self) {
        if self.active {
            end_payload_forwarding();
        }
    }
}

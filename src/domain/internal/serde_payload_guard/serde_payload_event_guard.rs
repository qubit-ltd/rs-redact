// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Scoped suspension of forwarding during a child Serde event.

use super::super::redact_serialize_scope::restore_payload_forwarding;
use super::super::redact_serialize_scope::suspend_payload_forwarding;

/// Suspends a forwarding credential while a new user `Serialize` value runs.
pub(in crate::domain::internal) struct SerdePayloadEventGuard {
    /// Forwarding depth saved before the child event, or `None` without an
    /// active budget. `Some(0)` still represents an active budget whose
    /// forwarding depth must be restored.
    previous: Option<usize>,
}

impl SerdePayloadEventGuard {
    /// Opens a child event boundary in the current structured budget.
    ///
    /// # Returns
    ///
    /// A guard that restores the matching scope state when dropped.
    #[must_use]
    #[inline]
    pub(in crate::domain::internal) fn new() -> Self {
        Self {
            previous: suspend_payload_forwarding(),
        }
    }
}

impl Drop for SerdePayloadEventGuard {
    /// Restores the forwarding state saved before the child event.
    ///
    /// This runs on normal return and panic unwinding, but not on abort or if
    /// the guard is leaked.
    #[inline]
    fn drop(&mut self) {
        restore_payload_forwarding(self.previous);
    }
}

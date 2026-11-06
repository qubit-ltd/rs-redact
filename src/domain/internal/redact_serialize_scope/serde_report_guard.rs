// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Observer lifetime and cleanup for structured serialization reports.

use std::cell::RefCell as Cell;
use std::rc::Rc;

use super::STRUCTURED_SERDE_BUDGETS;
use super::StructuredSerdeReport;
use crate::RedactionReasons;

/// RAII observer for reasons recorded by the budget active at registration.
///
/// A guard registered without an active budget owns an empty sink that receives
/// no reasons. With an active budget, the sink observes later reason events on
/// that budget; nested independent budgets do not broadcast to it. Each active
/// observer on a budget receives the same later events. Its reasons accumulate
/// as a deduplicated set, and events before registration are not included.
///
/// Dropping the guard unregisters its sink. Normal return and unwinding run
/// this cleanup; `mem::forget` and process abort do not guarantee it.
#[cfg(feature = "json")]
pub(crate) struct SerdeReportGuard {
    /// Per-call reason sink shared with the active ledger, if any.
    pub(super) sink: Rc<Cell<StructuredSerdeReport>>,
}

#[cfg(feature = "json")]
impl SerdeReportGuard {
    /// Returns the cumulative distinct reasons observed since registration.
    ///
    /// A guard created outside an active structured budget always returns an
    /// empty set because its sink is not registered with a ledger.
    ///
    /// # Returns
    ///
    /// The reasons recorded after this guard was registered, with duplicates
    /// collapsed.
    #[must_use]
    #[inline]
    pub(crate) fn reasons(&self) -> RedactionReasons {
        self.sink.borrow().reasons
    }
}

#[cfg(feature = "json")]
impl Drop for SerdeReportGuard {
    /// Removes this sink from every currently stored budget ledger.
    ///
    /// Cleanup runs on ordinary drop and Rust unwinding. Forgetting the guard
    /// or aborting the process does not run this cleanup.
    fn drop(&mut self) {
        STRUCTURED_SERDE_BUDGETS.with(|slot| {
            for budget in slot.borrow_mut().iter_mut() {
                budget.reports.retain(|report| !Rc::ptr_eq(report, &self.sink));
            }
        });
    }
}

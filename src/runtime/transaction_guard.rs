// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Panic rollback guard for one public transaction operation.

use std::thread::panicking;

use super::resettable_session::ResettableSession;

/// Resets its borrowed session if user code unwinds before commit.
///
/// # Type Parameters
///
/// - `'session`: Exclusive borrow held until commit or guard destruction.
/// - `S`: Transaction mode that can replace its state after unwinding.
pub(super) struct TransactionGuard<'session, S: ResettableSession> {
    /// Borrowed mode-specific session restored if unwinding occurs.
    session: &'session mut S,
    /// Whether the guarded operation completed and retained its changes.
    committed: bool,
}

impl<'session, S: ResettableSession> TransactionGuard<'session, S> {
    /// Starts a rollback boundary for `session`.
    ///
    /// # Parameters
    ///
    /// - `session`: Active transaction to reset if user code unwinds.
    ///
    /// # Returns
    ///
    /// An uncommitted guard borrowing the transaction.
    #[must_use]
    #[inline(always)]
    pub(super) fn new(session: &'session mut S) -> Self {
        Self {
            session,
            committed: false,
        }
    }

    /// Borrows the active session for the guarded operation.
    ///
    /// # Returns
    ///
    /// A temporary mutable borrow of the guarded transaction.
    #[must_use]
    #[inline(always)]
    pub(super) fn session(&mut self) -> &mut S {
        self.session
    }

    /// Marks this operation as successfully completed.
    #[inline(always)]
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl<S: ResettableSession> Drop for TransactionGuard<'_, S> {
    /// Restores a fresh same-mode transaction only during panic unwinding.
    #[inline]
    fn drop(&mut self) {
        if !self.committed && panicking() {
            self.session.reset_transaction();
        }
    }
}

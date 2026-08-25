// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Panic rollback guard for one public transaction operation.

use super::resettable_session::ResettableSession;

/// Resets its borrowed session if user code unwinds before commit.
pub(super) struct TransactionGuard<'session, S: ResettableSession> {
    /// Borrowed mode-specific session restored if unwinding occurs.
    session: &'session mut S,
    /// Whether the guarded operation completed and retained its changes.
    committed: bool,
}

impl<'session, S: ResettableSession> TransactionGuard<'session, S> {
    /// Starts a rollback boundary for `session`.
    pub(super) fn new(session: &'session mut S) -> Self {
        Self {
            session,
            committed: false,
        }
    }

    /// Borrows the active session for the guarded operation.
    pub(super) fn session(&mut self) -> &mut S {
        self.session
    }

    /// Marks this operation as successfully completed.
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl<S: ResettableSession> Drop for TransactionGuard<'_, S> {
    /// Restores a fresh same-mode transaction only during panic unwinding.
    fn drop(&mut self) {
        if !self.committed && std::thread::panicking() {
            self.session.reset_transaction();
        }
    }
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Panic rollback guard for one public transaction operation.

use super::RedactionSession;

/// Resets its borrowed session if user code unwinds before commit.
pub(super) struct TransactionGuard<'session> {
    session: &'session mut RedactionSession,
    committed: bool,
}

impl<'session> TransactionGuard<'session> {
    /// Starts a rollback boundary for `session`.
    pub(super) fn new(session: &'session mut RedactionSession) -> Self {
        Self {
            session,
            committed: false,
        }
    }

    /// Borrows the active session for the guarded operation.
    pub(super) fn session(&mut self) -> &mut RedactionSession {
        self.session
    }

    /// Marks this operation as successfully completed.
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for TransactionGuard<'_> {
    fn drop(&mut self) {
        if !self.committed && std::thread::panicking() {
            self.session.reset_transaction();
        }
    }
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Same-mode restoration capability for panic rollback.

/// Restores the same transaction mode after a user callback panics.
pub(super) trait ResettableSession {
    /// Discards unpublished state and installs a fresh same-mode transaction.
    fn reset_transaction(&mut self);
}

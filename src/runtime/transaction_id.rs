// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Monotonic identities for independently published transactions.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Process-local source for transaction identities.
static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);

/// Returns a fresh non-zero transaction identity.
#[inline]
pub(super) fn next_transaction_id() -> u64 {
    NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed)
}

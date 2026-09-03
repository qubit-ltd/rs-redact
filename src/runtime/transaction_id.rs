// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Monotonic identities for independently published transactions.

#[cfg(test)]
use std::cell::Cell;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

// Per-test-thread observation of identity allocation without interference
// from concurrently executing tests.
#[cfg(test)]
thread_local! {
    static CURRENT_THREAD_ISSUED_IDS: Cell<usize> = const { Cell::new(0) };
}

/// Process-local source for transaction identities.
static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);

/// Returns a fresh non-zero transaction identity.
#[inline]
pub(super) fn next_transaction_id() -> u64 {
    #[cfg(test)]
    CURRENT_THREAD_ISSUED_IDS.set(CURRENT_THREAD_ISSUED_IDS.get().saturating_add(1));
    NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::CURRENT_THREAD_ISSUED_IDS;
    use crate::Redactor;

    /// One-shot text publication does not allocate a batch-only transaction
    /// identity, while explicitly starting a batch allocates exactly one.
    #[test]
    fn test_one_shot_redaction_does_not_allocate_batch_identity() {
        let before = CURRENT_THREAD_ISSUED_IDS.get();
        let redactor = Redactor::standard();

        let _ = redactor.redact_field("password", "raw-secret");
        assert_eq!(CURRENT_THREAD_ISSUED_IDS.get(), before);

        let _batch = redactor.batch();
        assert_eq!(CURRENT_THREAD_ISSUED_IDS.get(), before.saturating_add(1));
    }
}

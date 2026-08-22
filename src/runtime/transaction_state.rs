// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished mutable state owned by one redaction transaction.

use std::sync::Arc;

use super::publication_buffer::PublicationBuffer;
use super::redaction_runtime::RedactionRuntime;
use crate::RedactionPolicy;

/// All mutable accounting and unpublished output for one transaction.
pub struct TransactionState {
    pub(super) id: u64,
    pub(super) runtime: RedactionRuntime,
    pub(super) publication: PublicationBuffer,
}

impl TransactionState {
    /// Creates an empty transaction governed by `policy`.
    #[must_use]
    pub(super) fn new_text(policy: Arc<RedactionPolicy>, id: u64) -> Self {
        Self {
            id,
            runtime: RedactionRuntime::new(policy),
            publication: PublicationBuffer::text(),
        }
    }

    /// Creates state that publishes independently resolvable batch items.
    #[must_use]
    pub(super) fn new_batch(policy: Arc<RedactionPolicy>, id: u64) -> Self {
        Self {
            id,
            runtime: RedactionRuntime::new(policy),
            publication: PublicationBuffer::batch(),
        }
    }

    /// Creates state for a non-rendering sensitivity inspection.
    #[must_use]
    pub(super) fn new_inspection(policy: Arc<RedactionPolicy>, id: u64) -> Self {
        Self {
            id,
            runtime: RedactionRuntime::new_inspection(policy),
            publication: PublicationBuffer::inspection(),
        }
    }
}

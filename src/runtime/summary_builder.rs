// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable construction of transaction-owned redaction summaries.

use crate::RedactionSummary;

/// Transaction-local accounting builder that is converted to a public summary
/// only when a transaction publishes its result.
#[derive(Clone, Copy)]
pub(super) struct SummaryBuilder {
    summary: RedactionSummary,
}

impl SummaryBuilder {
    /// Creates an empty complete transaction summary.
    #[must_use]
    pub(super) const fn new() -> Self {
        Self {
            summary: RedactionSummary::complete(),
        }
    }

    /// Wraps an existing immutable summary as transaction-local state.
    #[must_use]
    pub(super) const fn from_summary(summary: RedactionSummary) -> Self {
        Self { summary }
    }

    /// Returns the completed immutable summary snapshot.
    #[must_use]
    pub(super) const fn build(self) -> RedactionSummary {
        self.summary
    }

    /// Merges an operation delta into this builder.
    #[must_use]
    pub(super) const fn merge(self, delta: RedactionSummary) -> Self {
        Self {
            summary: self.summary.merge(delta),
        }
    }

    /// Adds retained output bytes.
    #[must_use]
    pub(super) const fn with_added_output_bytes(self, bytes: usize) -> Self {
        Self {
            summary: self.summary.with_added_output_bytes(bytes),
        }
    }

    /// Records ordinary presented and inspected input bytes.
    #[must_use]
    pub(super) const fn with_input(self, presented: usize, inspected: usize) -> Self {
        Self {
            summary: self.summary.with_input(presented, inspected),
        }
    }

    /// Records source-aware input accounting.
    #[cfg(feature = "http")]
    #[must_use]
    pub(super) const fn with_source_input(
        self,
        presented: usize,
        inspected: usize,
        omitted: Option<usize>,
    ) -> Self {
        Self {
            summary: self
                .summary
                .with_source_input(presented, inspected, omitted),
        }
    }

    /// Records one admitted structural node at `depth`.
    #[must_use]
    pub(super) const fn with_domain_node(self, depth: usize) -> Self {
        Self {
            summary: self.summary.with_domain_node(depth),
        }
    }

    /// Records one admitted collection item.
    #[must_use]
    pub(super) const fn with_collection_item(self) -> Self {
        Self {
            summary: self.summary.with_collection_item(),
        }
    }

    /// Returns resource usage collected so far.
    #[must_use]
    pub(super) const fn usage(self) -> crate::RedactionUsage {
        self.summary.usage()
    }
}

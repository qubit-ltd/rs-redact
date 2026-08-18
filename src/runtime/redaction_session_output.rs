// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomically published output from one redaction session.

use std::collections::BTreeMap;

use crate::RedactedText;
use crate::RedactionOutput;
use crate::RedactionSummary;

/// Final output published after a session commits successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionSessionOutput {
    text: RedactedText,
    results: BTreeMap<String, RedactionOutput>,
    summary: RedactionSummary,
}

impl RedactionSessionOutput {
    /// Creates a published session output.
    pub(crate) fn new(
        text: RedactedText,
        results: BTreeMap<String, RedactionOutput>,
        summary: RedactionSummary,
    ) -> Self {
        Self { text, results, summary }
    }

    /// Returns the composed safe text.
    #[must_use]
    pub const fn text(&self) -> &RedactedText {
        &self.text
    }

    /// Returns the result staged under `key`, when present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&RedactionOutput> {
        self.results.get(key)
    }

    /// Returns all keyed results.
    #[must_use]
    pub const fn results(&self) -> &BTreeMap<String, RedactionOutput> {
        &self.results
    }

    /// Returns the aggregate summary.
    #[must_use]
    pub const fn summary(&self) -> &RedactionSummary {
        &self.summary
    }
}

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
    output: RedactionOutput,
    results: BTreeMap<String, RedactionOutput>,
}

impl RedactionSessionOutput {
    /// Creates a published session output.
    pub(crate) fn new(
        text: RedactedText,
        results: BTreeMap<String, RedactionOutput>,
        summary: RedactionSummary,
    ) -> Self {
        Self {
            output: RedactionOutput::new(text, summary),
            results,
        }
    }

    /// Returns the composed safe text.
    #[must_use]
    pub const fn text(&self) -> &RedactedText {
        self.output.text()
    }

    /// Returns the aggregate summary.
    #[must_use]
    pub const fn summary(&self) -> RedactionSummary {
        self.output.summary()
    }

    /// Returns the result staged under `key`, when present.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&RedactionOutput> {
        self.results.get(key)
    }

    /// Returns all keyed results.
    #[must_use]
    pub fn results(&self) -> impl ExactSizeIterator<Item = (&str, &RedactionOutput)> {
        self.results.iter().map(|(key, output)| (key.as_str(), output))
    }

    /// Consumes the published output into its composed and keyed parts.
    #[must_use]
    pub fn into_parts(self) -> (RedactionOutput, BTreeMap<String, RedactionOutput>) {
        (self.output, self.results)
    }
}

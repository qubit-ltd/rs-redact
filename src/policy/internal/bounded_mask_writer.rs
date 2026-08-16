// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Byte-bounded accumulation for masked values.

use std::fmt;

use qubit_budget::ResourceBudget;

use super::super::RedactionResource;

/// Accumulates at most a fixed number of UTF-8 bytes.
pub(in crate::policy) struct BoundedMaskWriter {
    /// Retained masked prefix.
    output: String,
    /// Exact accounting for retained masked bytes.
    budget: ResourceBudget<RedactionResource, usize>,
    /// Whether any complete masked bytes could not be retained.
    truncated: bool,
}

impl BoundedMaskWriter {
    /// Creates an empty bounded mask writer.
    ///
    /// # Parameters
    ///
    /// * `max_bytes` - Maximum retained UTF-8 bytes.
    ///
    /// # Returns
    ///
    /// An empty writer that grows only for retained masked bytes.
    #[must_use]
    pub(in crate::policy) fn new(max_bytes: usize) -> Self {
        Self {
            output: String::new(),
            budget: ResourceBudget::new(RedactionResource::Mask, max_bytes),
            truncated: false,
        }
    }

    /// Returns the retained masked prefix.
    ///
    /// # Returns
    ///
    /// The owned masked UTF-8 prefix within the configured byte budget.
    pub(in crate::policy) fn finish(self) -> (String, bool) {
        (self.output, self.truncated)
    }
}

impl fmt::Write for BoundedMaskWriter {
    /// Appends the longest UTF-8 prefix that fits the remaining budget.
    ///
    /// # Parameters
    ///
    /// * `value` - Masked text to append within the remaining byte budget.
    ///
    /// # Returns
    ///
    /// `Ok(())` after retaining the longest complete UTF-8 prefix that fits.
    ///
    /// # Errors
    ///
    /// This bounded in-memory writer does not return a formatting error.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = self.budget.remaining();
        let mut end = value.len().min(remaining);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.budget
            .try_consume(end)
            .expect("the bounded UTF-8 prefix must fit its mask budget");
        self.output.push_str(&value[..end]);
        self.truncated |= end < value.len();
        Ok(())
    }
}

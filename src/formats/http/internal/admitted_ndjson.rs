// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compact admitted NDJSON values with their source line positions.

use serde_json::Value;

/// Non-blank NDJSON records retained with their zero-based source line index.
///
/// `records` is sparse: blank source lines advance `line_count` but retain no
/// `Value`. Stored indices are strictly increasing and always less than
/// `line_count`. `line_count` counts lines yielded by `str::lines`; a terminal
/// newline is tracked separately and does not add an empty trailing line.
#[derive(Clone)]
pub(in crate::formats::http) struct AdmittedNdjson {
    /// Parsed non-blank values paired with their original zero-based line.
    records: Vec<(usize, Value)>,
    /// Number of source lines yielded so far by `str::lines`.
    line_count: usize,
    /// Whether the complete source ended in a newline.
    trailing_newline: bool,
}

impl AdmittedNdjson {
    /// Creates an empty admitted body with its source trailing-newline state.
    ///
    /// # Parameters
    ///
    /// - `trailing_newline`: Whether the complete source ends with a newline.
    ///
    /// # Returns
    ///
    /// An empty record collection with zero source lines and the supplied
    /// trailing-newline state; no record storage is allocated.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn new(trailing_newline: bool) -> Self {
        Self {
            records: Vec::new(),
            line_count: 0,
            trailing_newline,
        }
    }

    /// Returns the admitted records for in-place rendering.
    ///
    /// Callers may transform each `Value`, but must preserve every line index
    /// and the records' strictly increasing order; changing either breaks the
    /// association with the source lines.
    ///
    /// # Returns
    ///
    /// A mutable slice borrowed from this body, containing only non-blank
    /// records and their original line indices; no allocation is performed.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn records_mut(&mut self) -> &mut [(usize, Value)] {
        &mut self.records
    }

    /// Returns the number of source lines yielded by `str::lines`.
    ///
    /// # Returns
    ///
    /// The count of admitted blank and non-blank source lines, excluding an
    /// empty line after a terminal newline.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn line_count(&self) -> usize {
        self.line_count
    }

    /// Returns whether the complete source ended with a newline.
    ///
    /// # Returns
    ///
    /// `true` if the complete source ended with a newline, otherwise `false`.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn trailing_newline(&self) -> bool {
        self.trailing_newline
    }

    /// Advances the source line position without retaining an empty record.
    ///
    /// # Panics
    ///
    /// Panics if the source line count overflows `usize` when overflow checks
    /// are enabled.
    #[inline]
    pub(in crate::formats::http) fn push_blank(&mut self) {
        self.line_count += 1;
    }

    /// Retains a parsed record at the current source line and advances it.
    ///
    /// # Parameters
    ///
    /// - `value`: Parsed non-blank record moved into this collection without
    ///   cloning; appending may grow the record storage.
    ///
    /// # Panics
    ///
    /// Panics if the record storage's new capacity exceeds `isize::MAX` bytes,
    /// or if the source line count overflows `usize` when overflow checks are
    /// enabled.
    #[inline]
    pub(in crate::formats::http) fn push_value(&mut self, value: Value) {
        self.records.push((self.line_count, value));
        self.line_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::AdmittedNdjson;

    #[test]
    fn test_rr2_blank_lines_retain_no_record_slots() {
        let mut body = AdmittedNdjson::new(false);
        for _ in 0..65_000 {
            body.push_blank();
        }
        assert!(body.records.is_empty(), "blank lines must not retain records");
        assert_eq!(body.line_count, 65_000, "blank lines must advance the source position");

        body.push_value(json!({ "first": 1 }));
        body.push_blank();
        body.push_value(json!({ "second": 2 }));
        assert_eq!(body.records.len(), 2, "only non-blank records must be retained");
        assert_eq!(body.records[0].0, 65_000, "first record must follow the blank prefix");
        assert_eq!(
            body.records[1].0, 65_002,
            "interior blank line must preserve the index gap"
        );
        assert_eq!(body.line_count, 65_003, "all source lines must be counted");
    }
}

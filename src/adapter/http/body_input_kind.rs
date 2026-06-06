// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::redaction_markers::{
    INVALID_JSON_REDACTED,
    INVALID_NDJSON_REDACTED,
    INVALID_OR_TRUNCATED_JSON_REDACTED,
    INVALID_OR_TRUNCATED_NDJSON_REDACTED,
};

/// Body input kind used to select complete-body or preview rendering behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyInputKind {
    /// Complete body bytes.
    Complete,
    /// Caller-limited body prefix.
    Preview,
}

impl BodyInputKind {
    /// Returns output for an empty byte slice.
    ///
    /// # Parameters
    ///
    /// * `source_len` - Total source length.
    ///
    /// # Returns
    ///
    /// Empty complete body text or a preview marker.
    pub(super) fn empty_output(self, source_len: usize) -> String {
        match self {
            Self::Complete => String::new(),
            Self::Preview => {
                format!("<empty>{}", self.truncation_suffix(0, source_len))
            }
        }
    }

    /// Returns whether the provided bytes are a truncated preview.
    ///
    /// # Parameters
    ///
    /// * `bytes_len` - Available byte count.
    /// * `source_len` - Total source byte count.
    ///
    /// # Returns
    ///
    /// `true` only for previews whose source is longer than the prefix.
    pub(super) fn is_truncated(
        self,
        bytes_len: usize,
        source_len: usize,
    ) -> bool {
        self == Self::Preview && source_len > bytes_len
    }

    /// Returns the truncation suffix for rendered preview output.
    ///
    /// # Parameters
    ///
    /// * `bytes_len` - Rendered prefix byte count.
    /// * `source_len` - Total source byte count.
    ///
    /// # Returns
    ///
    /// Empty string for complete bodies and untruncated previews, otherwise a
    /// byte-count truncation marker.
    pub(super) fn truncation_suffix(
        self,
        bytes_len: usize,
        source_len: usize,
    ) -> String {
        if !self.is_truncated(bytes_len, source_len) {
            return String::new();
        }
        let truncated = source_len.saturating_sub(bytes_len);
        format!("...<truncated {truncated} bytes>")
    }

    /// Returns the JSON parse failure marker for this input kind.
    ///
    /// # Returns
    ///
    /// JSON redaction marker.
    pub(super) fn invalid_json_marker(self) -> &'static str {
        match self {
            Self::Complete => INVALID_JSON_REDACTED,
            Self::Preview => INVALID_OR_TRUNCATED_JSON_REDACTED,
        }
    }

    /// Returns the NDJSON parse failure marker for this input kind.
    ///
    /// # Returns
    ///
    /// NDJSON redaction marker.
    pub(super) fn invalid_ndjson_marker(self) -> &'static str {
        match self {
            Self::Complete => INVALID_NDJSON_REDACTED,
            Self::Preview => INVALID_OR_TRUNCATED_NDJSON_REDACTED,
        }
    }
}

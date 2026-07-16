// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::super::{
    BodyRedactionReason,
    redaction_markers::{
        INVALID_JSON_REDACTED,
        INVALID_NDJSON_REDACTED,
        INVALID_OR_TRUNCATED_JSON_REDACTED,
        INVALID_OR_TRUNCATED_NDJSON_REDACTED,
    },
};

/// Body input kind used to select complete-body or preview rendering behavior.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::adapter::http) enum BodyInputKind {
    /// Complete body bytes.
    Complete,
    /// Caller-limited body prefix.
    Preview,
}

impl BodyInputKind {
    /// Returns content for an empty byte slice.
    ///
    /// # Returns
    ///
    /// Empty complete-body text or an explicit preview marker.
    #[must_use]
    #[inline]
    pub(in crate::adapter::http) fn empty_content(self) -> String {
        match self {
            Self::Complete => String::new(),
            Self::Preview => "<empty>".to_string(),
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
    #[must_use]
    #[inline]
    pub(in crate::adapter::http) fn is_truncated(
        self,
        bytes_len: usize,
        source_len: usize,
    ) -> bool {
        self == Self::Preview && source_len > bytes_len
    }

    /// Returns the JSON parse failure marker for this input kind.
    ///
    /// # Returns
    ///
    /// JSON redaction marker.
    #[must_use]
    #[inline]
    pub(in crate::adapter::http) fn invalid_json_marker(self) -> &'static str {
        match self {
            Self::Complete => INVALID_JSON_REDACTED,
            Self::Preview => INVALID_OR_TRUNCATED_JSON_REDACTED,
        }
    }

    /// Returns the JSON parse failure reason for this input kind.
    ///
    /// # Returns
    ///
    /// JSON redaction reason.
    #[inline]
    pub(in crate::adapter::http) const fn invalid_json_reason(
        self,
    ) -> BodyRedactionReason {
        match self {
            Self::Complete => BodyRedactionReason::InvalidJson,
            Self::Preview => BodyRedactionReason::InvalidOrTruncatedJson,
        }
    }

    /// Returns the NDJSON parse failure marker for this input kind.
    ///
    /// # Returns
    ///
    /// NDJSON redaction marker.
    #[must_use]
    #[inline]
    pub(in crate::adapter::http) fn invalid_ndjson_marker(
        self,
    ) -> &'static str {
        match self {
            Self::Complete => INVALID_NDJSON_REDACTED,
            Self::Preview => INVALID_OR_TRUNCATED_NDJSON_REDACTED,
        }
    }

    /// Returns the NDJSON parse failure reason for this input kind.
    ///
    /// # Returns
    ///
    /// NDJSON redaction reason.
    #[inline]
    pub(in crate::adapter::http) const fn invalid_ndjson_reason(
        self,
    ) -> BodyRedactionReason {
        match self {
            Self::Complete => BodyRedactionReason::InvalidNdjson,
            Self::Preview => BodyRedactionReason::InvalidOrTruncatedNdjson,
        }
    }
}

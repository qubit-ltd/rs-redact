// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::super::{
    BodyRedactionReason,
    redaction_markers::{
        INVALID_FORM_URLENCODED_REDACTED,
        INVALID_JSON_REDACTED,
        INVALID_NDJSON_REDACTED,
        INVALID_OR_TRUNCATED_FORM_URLENCODED_REDACTED,
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

    /// Returns the JSON parse failure marker for the source state.
    ///
    /// # Parameters
    ///
    /// * `truncated` - Whether source bytes were omitted.
    ///
    /// # Returns
    ///
    /// JSON redaction marker.
    #[must_use]
    #[inline]
    pub(in crate::adapter::http) const fn invalid_json_marker(
        truncated: bool,
    ) -> &'static str {
        if truncated {
            INVALID_OR_TRUNCATED_JSON_REDACTED
        } else {
            INVALID_JSON_REDACTED
        }
    }

    /// Returns the JSON parse failure reason for the source state.
    ///
    /// # Parameters
    ///
    /// * `truncated` - Whether source bytes were omitted.
    ///
    /// # Returns
    ///
    /// JSON redaction reason.
    #[inline]
    pub(in crate::adapter::http) const fn invalid_json_reason(
        truncated: bool,
    ) -> BodyRedactionReason {
        if truncated {
            BodyRedactionReason::InvalidOrTruncatedJson
        } else {
            BodyRedactionReason::InvalidJson
        }
    }

    /// Returns the NDJSON parse failure marker for the source state.
    ///
    /// # Parameters
    ///
    /// * `truncated` - Whether source bytes were omitted.
    ///
    /// # Returns
    ///
    /// NDJSON redaction marker.
    #[must_use]
    #[inline]
    pub(in crate::adapter::http) fn invalid_ndjson_marker(
        truncated: bool,
    ) -> &'static str {
        if truncated {
            INVALID_OR_TRUNCATED_NDJSON_REDACTED
        } else {
            INVALID_NDJSON_REDACTED
        }
    }

    /// Returns the NDJSON parse failure reason for the source state.
    ///
    /// # Parameters
    ///
    /// * `truncated` - Whether source bytes were omitted.
    ///
    /// # Returns
    ///
    /// NDJSON redaction reason.
    #[inline]
    pub(in crate::adapter::http) const fn invalid_ndjson_reason(
        truncated: bool,
    ) -> BodyRedactionReason {
        if truncated {
            BodyRedactionReason::InvalidOrTruncatedNdjson
        } else {
            BodyRedactionReason::InvalidNdjson
        }
    }

    /// Returns the URL-encoded form parse failure marker for the source state.
    ///
    /// # Parameters
    ///
    /// * `truncated` - Whether source bytes were omitted.
    ///
    /// # Returns
    ///
    /// URL-encoded form redaction marker.
    #[must_use]
    #[inline]
    pub(in crate::adapter::http) const fn invalid_form_marker(
        truncated: bool,
    ) -> &'static str {
        if truncated {
            INVALID_OR_TRUNCATED_FORM_URLENCODED_REDACTED
        } else {
            INVALID_FORM_URLENCODED_REDACTED
        }
    }

    /// Returns the URL-encoded form parse failure reason for the source state.
    ///
    /// # Parameters
    ///
    /// * `truncated` - Whether source bytes were omitted.
    ///
    /// # Returns
    ///
    /// URL-encoded form redaction reason.
    #[inline]
    pub(in crate::adapter::http) const fn invalid_form_reason(
        truncated: bool,
    ) -> BodyRedactionReason {
        if truncated {
            BodyRedactionReason::InvalidOrTruncatedFormUrlEncoded
        } else {
            BodyRedactionReason::InvalidFormUrlEncoded
        }
    }
}

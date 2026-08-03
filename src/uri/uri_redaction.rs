// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured URI redaction results.

use std::fmt::{
    self,
    Debug,
    Display,
    Formatter,
};

use crate::LogSafeText;

use super::{
    UriComponent,
    UriRedactionReason,
    UriRedactionStatus,
};

/// A log-safe URI together with explainable processing metadata.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct UriRedaction {
    pub(crate) text: LogSafeText<'static>,
    pub(crate) status: UriRedactionStatus,
    pub(crate) reasons: Vec<UriRedactionReason>,
    pub(crate) components: Vec<UriComponent>,
    pub(crate) truncated: bool,
}

impl UriRedaction {
    /// Returns the log-safe URI text without exposing an unescaped source.
    #[must_use = "use the safe text when logging the URI"]
    #[inline]
    pub fn log_safe_text(&self) -> &LogSafeText<'static> {
        &self.text
    }

    /// Consumes the result and returns an owned log-safe string.
    #[must_use = "consume the result to obtain safe text"]
    #[inline]
    pub fn into_log_safe_text(self) -> String {
        self.text.into_owned()
    }

    /// Returns the overall processing status.
    #[must_use = "inspect the URI processing status"]
    #[inline]
    pub const fn status(&self) -> UriRedactionStatus {
        self.status
    }

    /// Returns all reasons recorded while processing the URI.
    #[must_use = "inspect the URI processing reasons"]
    #[inline]
    pub fn reasons(&self) -> &[UriRedactionReason] {
        &self.reasons
    }

    /// Returns whether any sensitive URI component was changed.
    #[must_use]
    #[inline]
    pub const fn has_sensitive_components(&self) -> bool {
        !self.components.is_empty()
    }

    /// Returns whether `component` was changed or classified as sensitive.
    #[must_use]
    #[inline]
    pub fn has_sensitive_component(&self, component: UriComponent) -> bool {
        self.components.contains(&component)
    }

    /// Returns whether `reason` was recorded.
    #[must_use]
    #[inline]
    pub fn has_reason(&self, reason: UriRedactionReason) -> bool {
        self.reasons.contains(&reason)
    }

    /// Returns whether output was shortened to fit the policy budget.
    #[must_use]
    #[inline]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl Debug for UriRedaction {
    /// Formats only safe text and redaction metadata.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UriRedaction")
            .field("text", &self.text.as_str())
            .field("status", &self.status)
            .field("reasons", &self.reasons)
            .field("components", &self.components)
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl Display for UriRedaction {
    /// Formats only the log-safe URI text.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text.as_str())
    }
}

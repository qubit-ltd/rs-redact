// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Metadata returned by URI inspection.

use super::UriComponent;
use super::UriRedactionReason;
use super::UriRedactionStatus;

/// URI processing metadata without rendering or retaining URI text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriInspection {
    pub(crate) status: UriRedactionStatus,
    pub(crate) reasons: Vec<UriRedactionReason>,
    pub(crate) components: Vec<UriComponent>,
}

impl UriInspection {
    /// Returns the overall processing status.
    #[must_use]
    #[inline]
    pub const fn status(&self) -> UriRedactionStatus {
        self.status
    }

    /// Returns all reasons recorded while processing the URI.
    #[must_use]
    #[inline]
    pub fn reasons(&self) -> &[UriRedactionReason] {
        &self.reasons
    }

    /// Returns whether any sensitive URI component was classified.
    #[must_use]
    #[inline]
    pub const fn has_sensitive_components(&self) -> bool {
        !self.components.is_empty()
    }

    /// Returns whether `component` was classified as sensitive.
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
}

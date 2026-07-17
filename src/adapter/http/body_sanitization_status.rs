// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Status of an HTTP body sanitization result.

use super::BodyRedactionReason;

/// Describes how an HTTP body was represented for diagnostics.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySanitizationStatus {
    /// The available body bytes were empty.
    Empty,
    /// All configured structured sanitization policies were applied. This does
    /// not claim that arbitrary secrets in non-sensitive fields were detected.
    Sanitized,
    /// The output contains at least one value that policy explicitly allowed
    /// unchanged.
    PassedThrough,
    /// The body was fully redacted for the supplied reason.
    Redacted(
        /// The reason the body could not be represented safely.
        BodyRedactionReason,
    ),
    /// The body was non-UTF-8 binary data represented by a size marker.
    Binary,
}

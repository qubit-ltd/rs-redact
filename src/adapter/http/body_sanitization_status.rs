// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Status of an HTTP body sanitization result.

use super::BodyRedactionReason;

/// Describes how an HTTP body was represented for diagnostics.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySanitizationStatus {
    /// The available body bytes were empty.
    Empty,
    /// The body was sanitized structurally or passed through by policy.
    Sanitized,
    /// The body was fully redacted for the supplied reason.
    Redacted(BodyRedactionReason),
    /// The body was non-UTF-8 binary data represented by a size marker.
    Binary,
}

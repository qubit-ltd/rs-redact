// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

/// Controls whether complete URL paths remain visible after sanitization.
///
/// This policy does not change masking of URL userinfo, fragments, or
/// recognized sensitive query values. Non-root paths are redacted by default
/// because path segments frequently contain opaque identifiers or credentials.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UrlPathPolicy {
    /// Preserves the complete URL path.
    Preserve,
    /// Replaces a non-root URL path with a fixed redaction marker.
    #[default]
    Redact,
}

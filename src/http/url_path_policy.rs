// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy for rendering URL paths in HTTP diagnostics.

/// Controls whether complete URL paths remain visible after redaction.
///
/// This policy does not affect URL userinfo, fragments, or recognized
/// sensitive query values. The standard policy preserves paths for diagnostic
/// usefulness; strict policies should select [`Self::Redact`] when paths may
/// contain opaque identifiers or credentials.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UrlPathPolicy {
    /// Preserves the complete URL path.
    #[default]
    Preserve,
    /// Replaces a non-root URL path with a fixed redaction marker.
    Redact,
}

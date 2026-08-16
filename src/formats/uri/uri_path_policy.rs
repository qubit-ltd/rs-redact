// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Path handling choices for URI redaction.

/// Controls whether URI paths are retained or replaced by a safe marker.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UriPathPolicy {
    /// Retains the raw path spelling.
    #[default]
    Preserve,
    /// Replaces a non-empty path with a legal percent-encoded marker.
    Redact,
}

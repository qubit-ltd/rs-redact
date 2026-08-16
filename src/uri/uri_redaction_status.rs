// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Overall URI redaction outcomes.

/// Describes the outcome of processing one URI string.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UriRedactionStatus {
    /// The input was valid and no component required a change.
    #[default]
    PassedThrough,
    /// The input was valid and one or more components were changed.
    Redacted,
    /// Parsing or strict component decoding failed, so a fixed marker was used.
    Invalid,
}

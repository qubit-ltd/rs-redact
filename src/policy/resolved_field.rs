// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomic field-resolution result used by redaction executors.

use super::Sensitivity;

/// Final field decision selected atomically by one lookup.
///
/// A sensitive result contains only the final level. The owning redaction
/// policy supplies the single mask table used to render that level.
#[derive(Clone, Copy)]
pub(crate) enum ResolvedField {
    /// A field is sensitive at the final maximum level.
    Sensitive {
        /// Final sensitivity after applying application and floor rules.
        sensitivity: Sensitivity,
    },
    /// Neither the application rules nor an enabled floor require redaction.
    PassThrough,
}

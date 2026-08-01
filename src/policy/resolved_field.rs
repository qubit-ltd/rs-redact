// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomic field-resolution result used by redaction executors.

use super::{
    MaskingPolicy,
    Sensitivity,
};

/// Final field decision selected atomically by one lookup.
///
/// The enum makes an invalid state impossible: a sensitive result always owns
/// the masking policy that must render it, while a pass-through result owns
/// neither value.
#[derive(Clone, Copy)]
pub(crate) enum ResolvedField<'a> {
    /// A field is sensitive at the final maximum level and must use `masking`.
    Sensitive {
        /// Final sensitivity after applying application and floor rules.
        sensitivity: Sensitivity,
        /// Masking policy belonging to the layer that owns the protection.
        masking: &'a MaskingPolicy,
    },
    /// Neither the application rules nor an enabled floor require redaction.
    PassThrough,
}

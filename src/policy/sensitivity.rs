// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Sensitivity levels used to select masking behavior.

/// Sensitivity assigned to a field or explicit value.
///
/// The strength order is `Low < Medium < High < Secret`.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// Low-risk value where keeping a small prefix and suffix is acceptable.
    Low,
    /// Moderately sensitive value where only a small suffix is retained.
    Medium,
    /// Highly sensitive value replaced by a fixed mask.
    High,
    /// Secret value replaced by the strongest configured mask.
    Secret,
}

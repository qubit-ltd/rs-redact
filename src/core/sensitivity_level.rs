// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
/// Sensitivity level associated with a field name.
///
/// Levels let callers use different masking policies for low-risk identifiers,
/// operational secrets, and values that should be fully redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SensitivityLevel {
    /// Low-risk value where keeping a small prefix and suffix is usually safe.
    Low,
    /// Moderately sensitive value where only a small suffix is retained.
    Medium,
    /// Highly sensitive value replaced by a fixed mask.
    High,
    /// Secret value replaced by the strongest configured mask.
    Secret,
}

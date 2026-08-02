// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
// qubit-style: allow source-test-pair
//! Reasons a field value was retained without masking.

/// Reason a field value was retained without masking.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassThroughReason {
    /// An application allow rule permitted the field.
    Allowed,
    /// No rule classified the field and the fallback is pass-through.
    Unknown,
}

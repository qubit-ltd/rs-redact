// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Streaming Display adapter for a borrowed masked JSON string.

use std::fmt;

use crate::MaskPolicy;

/// Borrows a mask policy and source string until the serializer writes them.
pub(crate) struct MaskedJsonText<'a> {
    /// Masking algorithm applied while formatting.
    policy: &'a MaskPolicy,
    /// Source string read only for edge-preserving mask policies.
    value: &'a str,
}

impl<'a> MaskedJsonText<'a> {
    /// Creates a lazy masked text view.
    #[must_use]
    #[inline]
    pub(crate) const fn new(policy: &'a MaskPolicy, value: &'a str) -> Self {
        Self { policy, value }
    }
}

impl fmt::Display for MaskedJsonText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.policy.write_masked(self.value, formatter)
    }
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Value-level logical in-place masking for textual forms.

use std::borrow::Cow;

use crate::MaskingPolicy;
use crate::Sensitivity;

/// Replaces a textual value according to one sensitivity level.
///
/// This trait changes the logical value only. It does not zeroize released
/// allocations or affect aliases, existing copies, or borrowed backing data.
pub trait RedactValueMut {
    /// Masks this value in place.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity selecting a mask.
    /// * `masking` - Complete masking configuration.
    fn redact_value_in_place(
        &mut self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    );
}

impl RedactValueMut for String {
    /// Replaces this owned string with the selected mask.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity selecting the mask.
    /// * `masking` - Complete masking configuration.
    #[inline]
    fn redact_value_in_place(
        &mut self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) {
        if let Cow::Owned(redacted) = masking.mask(level, self) {
            *self = redacted;
        }
    }
}

impl RedactValueMut for Cow<'_, str> {
    /// Replaces this borrowed-or-owned string with an owned selected mask.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity selecting the mask.
    /// * `masking` - Complete masking configuration.
    #[inline]
    fn redact_value_in_place(
        &mut self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) {
        if let Cow::Owned(redacted) = masking.mask(level, self.as_ref()) {
            *self = Cow::Owned(redacted);
        }
    }
}

impl<T: RedactValueMut> RedactValueMut for Option<T> {
    /// Redacts a present value while preserving the option shape.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity selecting the mask.
    /// * `masking` - Complete masking configuration.
    #[inline]
    fn redact_value_in_place(
        &mut self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) {
        if let Some(value) = self {
            value.redact_value_in_place(level, masking);
        }
    }
}

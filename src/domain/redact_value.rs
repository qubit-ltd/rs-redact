// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redaction contract for explicitly sensitive textual fields.

use std::borrow::Cow;

use super::internal::mask_byte_limit;
use crate::MaskingPolicy;
use crate::Sensitivity;
use crate::domain::RedactedValue;
use crate::output::MaskedValue;

/// Produces a borrowed or owned redacted representation of a textual value.
///
/// Implementations must not format or serialize the original value before
/// applying the selected masking policy.
/// Input accounting is not part of this capability's public contract:
///
/// ```compile_fail
/// use qubit_redact::domain::RedactValue;
///
/// let value = "secret";
/// let _ = value.redaction_input_bytes();
/// ```
pub trait RedactValue {
    /// Redacts this value at the requested sensitivity level.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the borrowed value and returned representation.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Mask algorithms configured for all sensitivity levels.
    ///
    /// # Returns
    ///
    /// A lazy typed representation preserving plain or optional container
    /// shape.
    #[must_use]
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a>;
}

impl RedactValue for str {
    /// Redacts a string slice without invoking its formatting traits.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime shared by the borrowed string, policy, and result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A plain redacted text representation.
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::Text(redact_text(self, level, masking))
    }
}

impl RedactValue for &str {
    /// Redacts a borrowed string without invoking its formatting traits.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime shared by the borrowed string, policy, and result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A plain redacted text representation.
    #[inline(always)]
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::Text(redact_text(self, level, masking))
    }
}

impl RedactValue for String {
    /// Redacts an owned string through a borrow of its contents.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime shared by the borrowed contents, policy, and result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A plain redacted text representation.
    #[inline(always)]
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::Text(redact_text(self.as_str(), level, masking))
    }
}

impl RedactValue for Cow<'_, str> {
    /// Redacts borrowed or owned cow text through its string contents.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime shared by the borrowed contents, policy, and result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A plain redacted text representation.
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::Text(redact_text(self.as_ref(), level, masking))
    }
}

impl RedactValue for Option<String> {
    /// Redacts an optional owned string while preserving its option shape.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime shared by the borrowed option, policy, and result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A present masked value or an absent option representation.
    #[inline(always)]
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        redact_option(self.as_deref(), level, masking)
    }
}

impl RedactValue for Option<&str> {
    /// Redacts an optional borrowed string while preserving its option shape.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime shared by the borrowed option, policy, and result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A present masked value or an absent option representation.
    #[inline(always)]
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        redact_option(*self, level, masking)
    }
}

impl RedactValue for Option<Cow<'_, str>> {
    /// Redacts optional cow text while preserving its option shape.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime shared by the borrowed option, policy, and result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask algorithm.
    /// * `masking` - Complete masking configuration.
    ///
    /// # Returns
    ///
    /// A present masked value or an absent option representation.
    #[inline(always)]
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        redact_option(self.as_deref(), level, masking)
    }
}

/// Masks text without consulting any formatting or serialization trait.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the raw text and any borrowed result.
///
/// # Parameters
///
/// * `value` - Raw textual contents to mask.
/// * `level` - Sensitivity level selecting the mask algorithm.
/// * `masking` - Complete masking configuration.
///
/// # Returns
///
/// Typed redacted text preserving a borrow when the mask allows it.
#[inline(always)]
#[must_use]
fn redact_text<'a>(
    value: &'a str,
    level: Sensitivity,
    masking: &MaskingPolicy,
) -> MaskedValue<'a> {
    let redacted = match mask_byte_limit() {
        Some(max_bytes) => masking.mask_bounded(level, value, max_bytes),
        None => masking.mask(level, value),
    };
    MaskedValue::new(redacted)
}

/// Masks optional text without inspecting it when absent.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the optional text and any borrowed result.
///
/// # Parameters
///
/// * `value` - Optional raw textual contents to mask.
/// * `level` - Sensitivity level selecting the mask algorithm.
/// * `masking` - Complete masking configuration.
///
/// # Returns
///
/// [`RedactedValue::Some`] containing masked text when `value` is present, or
/// [`RedactedValue::None`] when it is absent.
#[must_use]
fn redact_option<'a>(
    value: Option<&'a str>,
    level: Sensitivity,
    masking: &MaskingPolicy,
) -> RedactedValue<'a> {
    match value {
        Some(value) => RedactedValue::Some(redact_text(value, level, masking)),
        None => RedactedValue::None,
    }
}

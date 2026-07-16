// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::borrow::Cow;

/// Strategy used to mask one sensitive field value.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskPolicy {
    /// Replaces non-empty values with a fixed replacement string.
    Fixed {
        /// Replacement used for non-empty values.
        replacement: String,
    },
    /// Preserves a prefix and suffix for diagnosability.
    PreserveEdges {
        /// Number of leading Unicode scalar values to retain.
        prefix_chars: usize,
        /// Number of trailing Unicode scalar values to retain.
        suffix_chars: usize,
        /// Replacement inserted between retained edges.
        replacement: String,
        /// Values at or below this character length are fully masked.
        full_mask_below_or_equal: usize,
    },
    /// Preserves only the final part of the value.
    PreserveSuffix {
        /// Number of trailing Unicode scalar values to retain.
        suffix_chars: usize,
        /// Replacement inserted before the retained suffix.
        replacement: String,
        /// Values at or below this character length are fully masked.
        full_mask_below_or_equal: usize,
    },
    /// Removes non-empty values entirely.
    Empty,
}

impl MaskPolicy {
    /// Creates a fixed-replacement mask policy.
    ///
    /// # Parameters
    ///
    /// * `replacement` - Replacement used for non-empty values.
    ///
    /// # Returns
    ///
    /// A mask policy that replaces non-empty values with `replacement`.
    #[inline]
    pub fn fixed(replacement: &str) -> Self {
        Self::Fixed {
            replacement: replacement.to_string(),
        }
    }

    /// Creates an edge-preserving mask policy.
    ///
    /// # Parameters
    ///
    /// * `prefix_chars` - Number of leading characters to retain.
    /// * `suffix_chars` - Number of trailing characters to retain.
    /// * `replacement` - Replacement inserted between retained edges.
    /// * `full_mask_below_or_equal` - Character length threshold for full
    ///   masks.
    ///
    /// # Returns
    ///
    /// A mask policy that keeps selected value edges for long values.
    #[inline]
    pub fn preserve_edges(
        prefix_chars: usize,
        suffix_chars: usize,
        replacement: &str,
        full_mask_below_or_equal: usize,
    ) -> Self {
        Self::PreserveEdges {
            prefix_chars,
            suffix_chars,
            replacement: replacement.to_string(),
            full_mask_below_or_equal,
        }
    }

    /// Creates a suffix-preserving mask policy.
    ///
    /// # Parameters
    ///
    /// * `suffix_chars` - Number of trailing characters to retain.
    /// * `replacement` - Replacement inserted before the suffix.
    /// * `full_mask_below_or_equal` - Character length threshold for full
    ///   masks.
    ///
    /// # Returns
    ///
    /// A mask policy that keeps only the selected trailing characters.
    #[inline]
    pub fn preserve_suffix(
        suffix_chars: usize,
        replacement: &str,
        full_mask_below_or_equal: usize,
    ) -> Self {
        Self::PreserveSuffix {
            suffix_chars,
            replacement: replacement.to_string(),
            full_mask_below_or_equal,
        }
    }

    /// Creates a policy that removes non-empty values.
    ///
    /// # Returns
    ///
    /// A mask policy that returns an empty value for every non-empty input.
    #[inline(always)]
    pub const fn empty() -> Self {
        Self::Empty
    }

    /// Masks one value according to this policy.
    ///
    /// Empty values are preserved as empty because they do not leak sensitive
    /// material and keeping them empty preserves field semantics.
    ///
    /// # Parameters
    ///
    /// * `value` - Field value to mask.
    ///
    /// # Returns
    ///
    /// Borrowed `value` when it is empty, otherwise an owned masked value.
    #[must_use = "use the returned masked value instead of the original value"]
    pub fn mask<'a>(&self, value: &'a str) -> Cow<'a, str> {
        if value.is_empty() {
            return Cow::Borrowed(value);
        }
        match self {
            Self::Fixed { replacement } => Cow::Owned(replacement.clone()),
            Self::PreserveEdges {
                prefix_chars,
                suffix_chars,
                replacement,
                full_mask_below_or_equal,
            } => Cow::Owned(mask_preserving_edges(
                value,
                *prefix_chars,
                *suffix_chars,
                replacement,
                *full_mask_below_or_equal,
            )),
            Self::PreserveSuffix {
                suffix_chars,
                replacement,
                full_mask_below_or_equal,
            } => Cow::Owned(mask_preserving_suffix(
                value,
                *suffix_chars,
                replacement,
                *full_mask_below_or_equal,
            )),
            Self::Empty => Cow::Owned(String::new()),
        }
    }

    /// Returns the mask for a non-empty value when it does not depend on that
    /// value's contents.
    ///
    /// # Returns
    ///
    /// `Some(mask)` for fixed and empty policies, otherwise `None` when the
    /// input value must be inspected to preserve selected characters.
    #[cfg(feature = "http")]
    #[inline]
    pub(crate) fn value_independent_non_empty_mask(&self) -> Option<&str> {
        match self {
            Self::Fixed { replacement } => Some(replacement),
            Self::Empty => Some(""),
            Self::PreserveEdges { .. } | Self::PreserveSuffix { .. } => None,
        }
    }
}

/// Masks a value while preserving a prefix and suffix.
///
/// # Parameters
///
/// * `value` - Field value to mask.
/// * `prefix_chars` - Number of leading characters to retain.
/// * `suffix_chars` - Number of trailing characters to retain.
/// * `replacement` - Replacement inserted between retained edges.
/// * `full_mask_below_or_equal` - Character length threshold for full masks.
///
/// # Returns
///
/// Owned masked value.
#[must_use = "use the returned masked value instead of the original value"]
fn mask_preserving_edges(
    value: &str,
    prefix_chars: usize,
    suffix_chars: usize,
    replacement: &str,
    full_mask_below_or_equal: usize,
) -> String {
    let char_count = value.chars().count();
    if char_count <= full_mask_below_or_equal
        || char_count <= prefix_chars.saturating_add(suffix_chars)
    {
        return replacement.to_string();
    }
    let prefix_end = value
        .char_indices()
        .nth(prefix_chars)
        .map_or(value.len(), |(index, _)| index);
    let suffix_start = value
        .char_indices()
        .nth(char_count - suffix_chars)
        .map_or(value.len(), |(index, _)| index);
    let mut masked = String::with_capacity(
        prefix_end + replacement.len() + value.len() - suffix_start,
    );
    masked.push_str(&value[..prefix_end]);
    masked.push_str(replacement);
    masked.push_str(&value[suffix_start..]);
    masked
}

/// Masks a value while preserving only a suffix.
///
/// # Parameters
///
/// * `value` - Field value to mask.
/// * `suffix_chars` - Number of trailing characters to retain.
/// * `replacement` - Replacement inserted before the retained suffix.
/// * `full_mask_below_or_equal` - Character length threshold for full masks.
///
/// # Returns
///
/// Owned masked value.
#[must_use = "use the returned masked value instead of the original value"]
fn mask_preserving_suffix(
    value: &str,
    suffix_chars: usize,
    replacement: &str,
    full_mask_below_or_equal: usize,
) -> String {
    let char_count = value.chars().count();
    if char_count <= full_mask_below_or_equal || char_count <= suffix_chars {
        return replacement.to_string();
    }
    let suffix_start = value
        .char_indices()
        .nth(char_count - suffix_chars)
        .map_or(value.len(), |(index, _)| index);
    let mut masked =
        String::with_capacity(replacement.len() + value.len() - suffix_start);
    masked.push_str(replacement);
    masked.push_str(&value[suffix_start..]);
    masked
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Algorithms for masking one sensitive value.

use std::borrow::Cow;

/// Strategy used to mask one sensitive field value.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskPolicy {
    /// Replaces non-empty values with a fixed replacement string.
    #[non_exhaustive]
    Fixed {
        /// Replacement used for non-empty values.
        replacement: String,
    },
    /// Preserves a prefix and suffix for diagnosability.
    #[non_exhaustive]
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
    #[non_exhaustive]
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
    /// Creates a fixed-replacement policy.
    ///
    /// # Parameters
    ///
    /// * `replacement` - Text returned for every non-empty value.
    ///
    /// # Returns
    ///
    /// A fixed-replacement mask policy.
    #[inline]
    pub fn fixed(replacement: &str) -> Self {
        Self::Fixed {
            replacement: replacement.to_string(),
        }
    }

    /// Creates a policy that retains `prefix_chars` and `suffix_chars` scalars.
    ///
    /// Values no longer than `full_mask_below_or_equal`, or too short to keep
    /// both requested edges without overlap, are replaced completely.
    ///
    /// # Parameters
    ///
    /// * `prefix_chars` - Number of leading Unicode scalars to retain.
    /// * `suffix_chars` - Number of trailing Unicode scalars to retain.
    /// * `replacement` - Text inserted between retained edges.
    /// * `full_mask_below_or_equal` - Scalar-count threshold for full masking.
    ///
    /// # Returns
    ///
    /// An edge-preserving mask policy.
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

    /// Creates a policy that retains `suffix_chars` trailing Unicode scalars.
    ///
    /// Values no longer than `full_mask_below_or_equal`, or no longer than the
    /// requested suffix, are replaced completely.
    ///
    /// # Parameters
    ///
    /// * `suffix_chars` - Number of trailing Unicode scalars to retain.
    /// * `replacement` - Text inserted before the retained suffix.
    /// * `full_mask_below_or_equal` - Scalar-count threshold for full masking.
    ///
    /// # Returns
    ///
    /// A suffix-preserving mask policy.
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

    /// Creates a policy that removes every non-empty value.
    ///
    /// # Returns
    ///
    /// A mask policy that produces an empty result.
    #[inline(always)]
    pub const fn empty() -> Self {
        Self::Empty
    }

    /// Masks `value` according to this policy.
    ///
    /// Empty values remain borrowed and empty. Non-empty values return an
    /// owned mask, with edge counts measured in Unicode scalar values.
    ///
    /// # Parameters
    ///
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// The borrowed empty input or an owned masked value.
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
}

/// Masks `value` while preserving requested Unicode scalar edges.
///
/// # Parameters
///
/// * `value` - Non-empty value to mask.
/// * `prefix_chars` - Number of leading scalars to retain.
/// * `suffix_chars` - Number of trailing scalars to retain.
/// * `replacement` - Text inserted between retained edges.
/// * `full_mask_below_or_equal` - Scalar-count threshold for full masking.
///
/// # Returns
///
/// An owned masked value.
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

/// Masks `value` while preserving requested trailing Unicode scalar values.
///
/// # Parameters
///
/// * `value` - Non-empty value to mask.
/// * `suffix_chars` - Number of trailing scalars to retain.
/// * `replacement` - Text inserted before the retained suffix.
/// * `full_mask_below_or_equal` - Scalar-count threshold for full masking.
///
/// # Returns
///
/// An owned masked value.
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

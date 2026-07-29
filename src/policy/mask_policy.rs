// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Algorithms for masking one sensitive value.

use std::borrow::Cow;
use std::fmt::{
    self,
    Write,
};

use super::internal::BoundedMaskWriter;

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
    pub const fn empty() -> Self {
        Self::Empty
    }

    /// Masks `value` according to this policy.
    ///
    /// Empty values remain borrowed and empty. Non-empty values return an
    /// owned mask, with edge counts measured in Unicode scalar values.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed result.
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

    /// Returns the complete replacement for a value whose contents are opaque.
    ///
    /// Edge-preserving policies cannot safely retain any part of an opaque
    /// value, so this method returns only their configured replacement.
    ///
    /// # Returns
    ///
    /// The complete configured replacement, or an empty string for
    /// [`Self::Empty`].
    #[must_use = "use the opaque replacement instead of formatting the original value"]
    #[inline(always)]
    pub fn opaque_mask(&self) -> &str {
        match self {
            Self::Fixed { replacement }
            | Self::PreserveEdges { replacement, .. }
            | Self::PreserveSuffix { replacement, .. } => replacement,
            Self::Empty => "",
        }
    }

    /// Masks a value without allocating beyond a caller-supplied byte limit.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed result.
    ///
    /// # Parameters
    ///
    /// * `value` - Value to mask.
    /// * `max_bytes` - Maximum bytes retained from the masked representation.
    ///
    /// # Returns
    ///
    /// Empty input remains borrowed; other results own at most `max_bytes`.
    pub(crate) fn mask_bounded<'a>(
        &self,
        value: &'a str,
        max_bytes: usize,
    ) -> Cow<'a, str> {
        if value.is_empty() {
            return Cow::Borrowed(value);
        }
        let mut writer = BoundedMaskWriter::new(max_bytes);
        let _ = self.write_masked(value, &mut writer);
        Cow::Owned(writer.finish())
    }

    /// Returns an opaque replacement without exceeding a byte limit.
    ///
    /// # Parameters
    ///
    /// * `max_bytes` - Maximum bytes retained from the replacement.
    ///
    /// # Returns
    ///
    /// An owned UTF-8 prefix of the configured opaque replacement.
    #[must_use = "use the bounded opaque replacement instead of the original value"]
    pub(crate) fn opaque_mask_bounded(&self, max_bytes: usize) -> String {
        let mut writer = BoundedMaskWriter::new(max_bytes);
        let _ = writer.write_str(self.opaque_mask());
        writer.finish()
    }

    /// Writes a masked value directly without cloning fixed replacements.
    ///
    /// # Type Parameters
    ///
    /// * `W` - Formatting destination receiving the masked value.
    ///
    /// # Parameters
    ///
    /// * `value` - Non-empty value to mask.
    /// * `writer` - Formatting destination that may stop accepting output.
    ///
    /// # Returns
    ///
    /// `Ok(())` after writing the complete configured mask.
    ///
    /// # Errors
    ///
    /// Returns the destination formatting error unchanged.
    pub(crate) fn write_masked<W: fmt::Write>(
        &self,
        value: &str,
        writer: &mut W,
    ) -> fmt::Result {
        match self {
            Self::Fixed { replacement } => writer.write_str(replacement),
            Self::PreserveEdges {
                prefix_chars,
                suffix_chars,
                replacement,
                full_mask_below_or_equal,
            } => {
                let Some((prefix_end, suffix_start)) = preserved_edge_bounds(
                    value,
                    *prefix_chars,
                    *suffix_chars,
                    *full_mask_below_or_equal,
                ) else {
                    return writer.write_str(replacement);
                };
                writer.write_str(&value[..prefix_end])?;
                writer.write_str(replacement)?;
                writer.write_str(&value[suffix_start..])
            }
            Self::PreserveSuffix {
                suffix_chars,
                replacement,
                full_mask_below_or_equal,
            } => {
                let Some(suffix_start) = preserved_suffix_start(
                    value,
                    *suffix_chars,
                    *full_mask_below_or_equal,
                ) else {
                    return writer.write_str(replacement);
                };
                writer.write_str(replacement)?;
                writer.write_str(&value[suffix_start..])
            }
            Self::Empty => Ok(()),
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
    let Some((prefix_end, suffix_start)) = preserved_edge_bounds(
        value,
        prefix_chars,
        suffix_chars,
        full_mask_below_or_equal,
    ) else {
        return replacement.to_string();
    };
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
    let Some(suffix_start) =
        preserved_suffix_start(value, suffix_chars, full_mask_below_or_equal)
    else {
        return replacement.to_string();
    };
    let mut masked =
        String::with_capacity(replacement.len() + value.len() - suffix_start);
    masked.push_str(replacement);
    masked.push_str(&value[suffix_start..]);
    masked
}

/// Finds byte boundaries for preserving a prefix and suffix without counting
/// every scalar in a long value.
///
/// # Parameters
///
/// * `value` - UTF-8 text whose preserved edges are measured.
/// * `prefix_chars` - Number of leading scalar values to preserve.
/// * `suffix_chars` - Number of trailing scalar values to preserve.
/// * `full_mask_below_or_equal` - Length threshold requiring a complete mask.
///
/// # Returns
///
/// `Some((prefix_end, suffix_start))` when the value exceeds both full-mask
/// limits, or `None` when it must be masked completely.
fn preserved_edge_bounds(
    value: &str,
    prefix_chars: usize,
    suffix_chars: usize,
    full_mask_below_or_equal: usize,
) -> Option<(usize, usize)> {
    let edge_chars = prefix_chars.checked_add(suffix_chars)?;
    let required_chars = full_mask_below_or_equal.max(edge_chars);
    value.chars().nth(required_chars)?;
    let prefix_end = value.char_indices().nth(prefix_chars)?.0;
    let suffix_start = suffix_start(value, suffix_chars)?;
    Some((prefix_end, suffix_start))
}

/// Finds the byte boundary for preserving a suffix without counting every
/// scalar in a long value.
///
/// # Parameters
///
/// * `value` - UTF-8 text whose preserved suffix is measured.
/// * `suffix_chars` - Number of trailing scalar values to preserve.
/// * `full_mask_below_or_equal` - Length threshold requiring a complete mask.
///
/// # Returns
///
/// `Some(suffix_start)` when the value exceeds both full-mask limits, or
/// `None` when it must be masked completely.
fn preserved_suffix_start(
    value: &str,
    suffix_chars: usize,
    full_mask_below_or_equal: usize,
) -> Option<usize> {
    let required_chars = full_mask_below_or_equal.max(suffix_chars);
    value.chars().nth(required_chars)?;
    suffix_start(value, suffix_chars)
}

/// Finds the byte boundary before the final requested number of scalars.
///
/// # Parameters
///
/// * `value` - UTF-8 text whose suffix boundary is located.
/// * `suffix_chars` - Number of trailing scalar values in the suffix.
///
/// # Returns
///
/// `Some(index)` at a UTF-8 character boundary, or `None` when the value is
/// shorter than the requested suffix.
fn suffix_start(value: &str, suffix_chars: usize) -> Option<usize> {
    if suffix_chars == 0 {
        return Some(value.len());
    }
    value
        .char_indices()
        .rev()
        .nth(suffix_chars - 1)
        .map(|(index, _)| index)
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Byte-bounded display adapter for an already-redacted view.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Write as _;

use super::internal::mark_debug_output_exhausted;
use super::internal::with_debug_output_tracking;
use super::internal::with_mask_byte_limit;
use crate::LogOutputLimit;
use crate::text::internal::BoundedLogEscapeWriter;

/// A redacted formatting view whose log-safe output cannot exceed a byte limit.
///
/// The limit includes the complete `<truncated>` marker. Truncation preserves
/// UTF-8 character boundaries and never splits a generated escape sequence.
///
/// # Type Parameters
///
/// * `D` - Already-redacted debug value rendered by this adapter.
#[must_use = "format the bounded redacted view"]
pub struct BoundedRedactedDisplay<D> {
    /// Already-redacted debug view to render.
    value: D,
    /// Validated maximum output byte count.
    limit: LogOutputLimit,
}

impl<D> BoundedRedactedDisplay<D> {
    /// Creates a bounded display adapter around an already-redacted view.
    ///
    /// # Parameters
    ///
    /// * `value` - Redacted view whose compact debug representation is safe.
    /// * `limit` - Validated maximum output byte count.
    ///
    /// # Returns
    ///
    /// A bounded adapter implementing both `Debug` and `Display`.
    #[inline(always)]
    pub(crate) const fn new(value: D, limit: LogOutputLimit) -> Self {
        Self { value, limit }
    }
}

impl<D: Debug> Display for BoundedRedactedDisplay<D> {
    /// Writes escaped redacted output within the configured byte budget.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the bounded output.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when redacted formatting or the destination
    /// rejects output.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        format_bounded(&self.value, self.limit, formatter)
    }
}

impl<D: Debug> Debug for BoundedRedactedDisplay<D> {
    /// Writes the same bounded, log-safe representation as [`Display`].
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the bounded output.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when redacted formatting or the destination
    /// rejects output.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        format_bounded(&self.value, self.limit, formatter)
    }
}

/// Formats a type-erased debug value through one bounded implementation.
///
/// # Parameters
///
/// * `value` - Already-redacted debug view to format.
/// * `limit` - Validated maximum output byte count.
/// * `formatter` - Destination formatting context.
///
/// # Returns
///
/// The formatter result for the bounded output.
///
/// # Errors
///
/// Returns [`fmt::Error`] when redacted formatting or the destination rejects
/// output.
pub(super) fn format_bounded(
    value: &dyn Debug,
    limit: LogOutputLimit,
    formatter: &mut Formatter<'_>,
) -> fmt::Result {
    let mut writer = BoundedLogEscapeWriter::new(limit);
    let result = with_mask_byte_limit(limit.max_bytes(), || {
        with_debug_output_tracking(|| {
            let mut tracked = TrackedLogWriter(&mut writer);
            write!(&mut tracked, "{value:?}")
        })
    });
    if result.is_err() && !writer.is_truncated() {
        return Err(fmt::Error);
    }
    formatter.write_str(&writer.finish())
}

/// Formats a redacted debug value with the policy output limit while preserving
/// the caller's alternate-debug flag.
///
/// Unlike [`format_bounded`], this helper preserves the native `Debug` output
/// rather than applying log escaping. The redacted value is still bounded
/// before it reaches the caller's formatter.
pub(super) fn format_debug_bounded(
    value: &dyn Debug,
    limit: LogOutputLimit,
    formatter: &mut Formatter<'_>,
) -> fmt::Result {
    let mut writer = BoundedDebugWriter::new(limit);
    let result = with_mask_byte_limit(limit.max_bytes(), || {
        with_debug_output_tracking(|| {
            if formatter.alternate() {
                write!(&mut writer, "{value:#?}")
            } else {
                write!(&mut writer, "{value:?}")
            }
        })
    });
    if result.is_err() && !writer.is_truncated() {
        return Err(fmt::Error);
    }
    formatter.write_str(&writer.finish())
}

/// Retains a bounded native debug prefix and appends the truncation marker.
struct BoundedDebugWriter {
    output: String,
    limit: usize,
    truncated: bool,
}

impl BoundedDebugWriter {
    /// Creates an empty bounded debug writer.
    fn new(limit: LogOutputLimit) -> Self {
        Self {
            output: String::with_capacity(limit.max_bytes()),
            limit: limit.max_bytes(),
            truncated: false,
        }
    }

    /// Returns whether a write exceeded the configured limit.
    fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Finishes the bounded output with a complete truncation marker.
    fn finish(mut self) -> String {
        if self.truncated {
            let marker = "<truncated>";
            let prefix_limit = self.limit.saturating_sub(marker.len());
            self.output
                .truncate(floor_char_boundary(&self.output, prefix_limit));
            self.output.push_str(marker);
        }
        self.output
    }
}

impl fmt::Write for BoundedDebugWriter {
    /// Appends a complete UTF-8 prefix or marks the output truncated.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated {
            return Err(fmt::Error);
        }
        let next_len = self.output.len().saturating_add(value.len());
        if next_len <= self.limit {
            self.output.push_str(value);
            return Ok(());
        }

        let payload_limit = self.limit.saturating_sub("<truncated>".len());
        let remaining = payload_limit.saturating_sub(self.output.len());
        if remaining > 0 {
            let prefix = value
                .get(..remaining)
                .or_else(|| value.get(..floor_char_boundary(value, remaining)))
                .unwrap_or_default();
            self.output.push_str(prefix);
        }
        self.truncated = true;
        mark_debug_output_exhausted();
        Err(fmt::Error)
    }
}

/// Marks log-safe writer truncation in the active container context.
struct TrackedLogWriter<'writer>(&'writer mut BoundedLogEscapeWriter);

impl fmt::Write for TrackedLogWriter<'_> {
    /// Forwards a fragment and records whether the bounded writer truncated it.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let result = self.0.write_str(value);
        if self.0.is_truncated() {
            mark_debug_output_exhausted();
        }
        result
    }
}

/// Returns the greatest UTF-8 boundary not greater than `limit`.
fn floor_char_boundary(value: &str, limit: usize) -> usize {
    let mut boundary = limit.min(value.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

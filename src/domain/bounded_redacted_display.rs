// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Byte-bounded display adapter for an already-redacted view.

use std::fmt::{self, Debug, Display, Formatter, Write as _};

use crate::{LogOutputLimit, text::internal::BoundedLogEscapeWriter};

use super::internal::with_mask_byte_limit;

/// A redacted display view whose log-safe output cannot exceed a byte limit.
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
    /// A display-only bounded adapter.
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
fn format_bounded(
    value: &dyn Debug,
    limit: LogOutputLimit,
    formatter: &mut Formatter<'_>,
) -> fmt::Result {
    let mut writer = BoundedLogEscapeWriter::new(limit);
    let result = with_mask_byte_limit(limit.max_bytes(), || write!(&mut writer, "{value:?}"));
    if result.is_err() && !writer.is_truncated() {
        return Err(fmt::Error);
    }
    formatter.write_str(&writer.finish())
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Byte-bounded display adapter for an already-redacted view.

use std::cell::Cell;
use std::fmt::{self, Debug, Display, Formatter, Write as _};

use crate::{LogOutputLimit, text::internal::BoundedLogEscapeWriter};

/// A redacted display view whose log-safe output cannot exceed a byte limit.
///
/// The limit includes the complete `<truncated>` marker. Truncation preserves
/// UTF-8 character boundaries and never splits a generated escape sequence.
#[must_use = "format the bounded redacted view"]
pub struct BoundedRedactedDisplay<D> {
    /// Already-redacted debug view to render.
    value: D,
    /// Validated maximum output byte count.
    limit: LogOutputLimit,
}

thread_local! {
    /// Active per-thread allocation ceiling for masks rendered by this adapter.
    static MASK_BYTE_LIMIT: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Restores the preceding bounded-mask allocation context on scope exit.
struct MaskByteLimitReset<'a> {
    /// Thread-local context whose previous value must be restored.
    context: &'a Cell<Option<usize>>,
    /// Context value active before entering the bounded formatter.
    previous: Option<usize>,
}

impl Drop for MaskByteLimitReset<'_> {
    /// Restores the context even when formatting exits through an error or
    /// panic.
    fn drop(&mut self) {
        self.context.set(self.previous);
    }
}

/// Executes `operation` while bounding each materialized mask on this thread.
///
/// # Parameters
///
/// * `max_bytes` - Maximum bytes retained by one materialized mask.
/// * `operation` - Formatting operation executed inside the bounded context.
///
/// # Returns
///
/// The result produced by `operation` after restoring any previous context.
pub(super) fn with_mask_byte_limit<T>(max_bytes: usize, operation: impl FnOnce() -> T) -> T {
    MASK_BYTE_LIMIT.with(|context| {
        let previous = context.replace(Some(max_bytes));
        let _reset = MaskByteLimitReset { context, previous };
        operation()
    })
}

/// Returns the active per-thread materialized-mask ceiling, when bounded.
///
/// # Returns
///
/// `Some(max_bytes)` while bounded display formatting is active, or `None`
/// for ordinary unbounded redaction.
#[inline(always)]
pub(super) fn mask_byte_limit() -> Option<usize> {
    MASK_BYTE_LIMIT.with(Cell::get)
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

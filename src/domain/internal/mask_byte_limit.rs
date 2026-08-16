// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Thread-local bounded-mask formatting context.

use std::cell::Cell;

use super::mask_byte_limit_reset::MaskByteLimitReset;

thread_local! {
    /// Active per-thread allocation ceiling for masks rendered by this adapter.
    static MASK_BYTE_LIMIT: Cell<Option<usize>> = const { Cell::new(None) };
    /// Whether the active bounded debug destination rejected output.
    static DEBUG_OUTPUT_EXHAUSTED: Cell<bool> = const { Cell::new(false) };
}

/// Restores a nested debug-output exhaustion context.
struct DebugOutputReset<'a> {
    context: &'a Cell<bool>,
    previous: bool,
}

impl Drop for DebugOutputReset<'_> {
    /// Restores the previous debug-output state when the guard leaves scope.
    fn drop(&mut self) {
        self.context.set(self.previous);
    }
}

/// Executes `operation` while bounding each materialized mask on this thread.
///
/// A nested operation may tighten the active ceiling but cannot widen a
/// ceiling established by an outer bounded formatter.
///
/// # Type Parameters
///
/// * `T` - Result type produced by the bounded operation.
///
/// # Parameters
///
/// * `max_bytes` - Maximum bytes retained by one materialized mask.
/// * `operation` - Formatting operation executed inside the bounded context.
///
/// # Returns
///
/// The result produced by `operation` after restoring any previous context.
pub(crate) fn with_mask_byte_limit<T>(
    max_bytes: usize,
    operation: impl FnOnce() -> T,
) -> T {
    MASK_BYTE_LIMIT.with(|context| {
        let previous = context.get();
        let effective =
            previous.map_or(max_bytes, |previous| previous.min(max_bytes));
        context.set(Some(effective));
        let _reset = MaskByteLimitReset::new(context, previous);
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
pub(crate) fn mask_byte_limit() -> Option<usize> {
    MASK_BYTE_LIMIT.with(Cell::get)
}

/// Executes one bounded render with an independently tracked writer state.
pub(crate) fn with_debug_output_tracking<T>(
    operation: impl FnOnce() -> T,
) -> T {
    DEBUG_OUTPUT_EXHAUSTED.with(|context| {
        let previous = context.replace(false);
        let _reset = DebugOutputReset { context, previous };
        operation()
    })
}

/// Marks the active bounded debug destination exhausted.
#[inline(always)]
pub(crate) fn mark_debug_output_exhausted() {
    DEBUG_OUTPUT_EXHAUSTED.with(|context| context.set(true));
}

/// Returns whether the active container destination has truncated.
#[inline(always)]
pub(crate) fn debug_output_exhausted() -> bool {
    DEBUG_OUTPUT_EXHAUSTED.with(Cell::get)
}

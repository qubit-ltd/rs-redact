// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Scope guard for bounded-mask formatting context.

use std::cell::Cell;

/// Restores the preceding bounded-mask allocation context on scope exit.
pub(super) struct MaskByteLimitReset<'a> {
    /// Thread-local context whose previous value must be restored.
    context: &'a Cell<Option<usize>>,
    /// Context value active before entering the bounded formatter.
    previous: Option<usize>,
}

impl<'a> MaskByteLimitReset<'a> {
    /// Creates a guard that restores `previous` in `context` on scope exit.
    ///
    /// # Parameters
    ///
    /// * `context` - Thread-local context whose value must be restored.
    /// * `previous` - Value that was active before the bounded operation.
    ///
    /// # Returns
    ///
    /// A scope guard that restores the context when dropped.
    #[inline(always)]
    pub(super) const fn new(context: &'a Cell<Option<usize>>, previous: Option<usize>) -> Self {
        Self { context, previous }
    }
}

impl Drop for MaskByteLimitReset<'_> {
    /// Restores the context even when formatting exits through an error or
    /// panic.
    fn drop(&mut self) {
        self.context.set(self.previous);
    }
}

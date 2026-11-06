// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazily admitted process command item iteration.

use crate::formats::argv::ArgvItem;
use crate::runtime::BatchSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Admits command arguments before the renderer can inspect them.
///
/// Borrows the batch transaction exclusively and consumes source items lazily,
/// charging structural and input budgets before exposing each borrowed item.
///
/// # Type Parameters
///
/// - `'session`: Lifetime of the exclusive batch transaction borrow.
/// - `'arguments`: Lifetime of the executable and argument values.
/// - `I`: Remaining argument source; iteration requires `Iterator<Item =
///   ArgvItem<'arguments>>`.
pub(in crate::formats::process) struct AdmittedCommandItems<'session, 'arguments, I> {
    /// Batch transaction charged before each argument is yielded.
    pub(in crate::formats::process) session: &'session mut BatchSession,
    /// Executable retained as the first pending argv item.
    pub(in crate::formats::process) program: Option<ArgvItem<'arguments>>,
    /// Remaining caller-provided arguments consumed lazily.
    pub(in crate::formats::process) arguments: I,
    /// Whether admission stopped the iterator before source exhaustion.
    pub(in crate::formats::process) failed: bool,
}

impl<'arguments, I> Iterator for AdmittedCommandItems<'_, 'arguments, I>
where
    I: Iterator<Item = ArgvItem<'arguments>>,
{
    /// One admitted executable or command-line argument.
    type Item = ArgvItem<'arguments>;

    /// Admits and returns the next command item without observing later input.
    ///
    /// # Returns
    ///
    /// `Some(item)` after charging its collection, node, and input budgets;
    /// `None` when the source is exhausted or admission is rejected. Rejection
    /// sets `failed` and may consume the rejected source item without yielding
    /// it; callers stop iteration when `None` is returned.
    fn next(&mut self) -> Option<Self::Item> {
        if self.program.is_none() && self.arguments.size_hint().1 == Some(0) {
            return None;
        }
        if !self.session.preflight_format_item(2) {
            self.failed = true;
            return None;
        }
        let item = self.program.take().or_else(|| self.arguments.next())?;
        if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
            self.failed = true;
            return None;
        }
        if !self.session.admit_input(item.value().as_encoded_bytes().len()) {
            self.failed = true;
            return None;
        }
        Some(item)
    }
}

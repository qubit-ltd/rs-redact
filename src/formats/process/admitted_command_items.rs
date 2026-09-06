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
pub(super) struct AdmittedCommandItems<'session, 'arguments, I> {
    /// Batch transaction charged before each argument is yielded.
    pub(super) session: &'session mut BatchSession,
    /// Executable retained as the first pending argv item.
    pub(super) program: Option<ArgvItem<'arguments>>,
    /// Remaining caller-provided arguments consumed lazily.
    pub(super) arguments: I,
    /// Whether admission stopped the iterator before source exhaustion.
    pub(super) failed: bool,
}

impl<'arguments, I> Iterator for AdmittedCommandItems<'_, 'arguments, I>
where
    I: Iterator<Item = ArgvItem<'arguments>>,
{
    /// One admitted executable or command-line argument.
    type Item = ArgvItem<'arguments>;

    /// Admits and returns the next command item without observing later input.
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
        if !self
            .session
            .admit_input(item.value().as_encoded_bytes().len())
        {
            self.failed = true;
            return None;
        }
        Some(item)
    }
}

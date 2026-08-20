// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazily admitted process command item iteration.

use crate::RedactionSession;
use crate::formats::argv::ArgvItem;

/// Admits command arguments before the renderer can inspect them.
pub(super) struct AdmittedCommandItems<'session, 'arguments, I> {
    pub(super) session: &'session mut RedactionSession,
    pub(super) program: Option<ArgvItem<'arguments>>,
    pub(super) arguments: I,
    pub(super) failed: bool,
}

impl<'arguments, I> Iterator for AdmittedCommandItems<'_, 'arguments, I>
where
    I: ExactSizeIterator<Item = ArgvItem<'arguments>>,
{
    type Item = ArgvItem<'arguments>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.program.is_none() && self.arguments.len() == 0 {
            return None;
        }
        if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
            self.failed = true;
            return None;
        }
        let item = self.program.take().or_else(|| self.arguments.next())?;
        if !self.session.admit_input(item.value().as_encoded_bytes().len()) {
            self.failed = true;
            return None;
        }
        Some(item)
    }
}

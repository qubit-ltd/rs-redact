// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Exact-size process command item iteration.

use crate::formats::argv::ArgvItem;

/// Streams a process executable followed by caller-provided arguments.
pub(super) struct CommandItems<'arguments, I> {
    program: Option<ArgvItem<'arguments>>,
    arguments: I,
}

impl<'arguments, I> CommandItems<'arguments, I> {
    /// Creates an iterator whose executable is the first argv item.
    pub(super) const fn new(program: ArgvItem<'arguments>, arguments: I) -> Self {
        Self {
            program: Some(program),
            arguments,
        }
    }
}

impl<'arguments, I> Iterator for CommandItems<'arguments, I>
where
    I: Iterator<Item = ArgvItem<'arguments>>,
{
    type Item = ArgvItem<'arguments>;

    fn next(&mut self) -> Option<Self::Item> {
        self.program.take().or_else(|| self.arguments.next())
    }
}

impl<'arguments, I> ExactSizeIterator for CommandItems<'arguments, I>
where
    I: ExactSizeIterator<Item = ArgvItem<'arguments>>,
{
    fn len(&self) -> usize {
        self.arguments.len().saturating_add(usize::from(self.program.is_some()))
    }
}

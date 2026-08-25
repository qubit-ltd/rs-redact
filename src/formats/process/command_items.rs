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
    /// Executable returned before caller-provided arguments.
    program: Option<ArgvItem<'arguments>>,
    /// Remaining command-line arguments.
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
    /// One executable or command-line argument in process order.
    type Item = ArgvItem<'arguments>;

    /// Returns the executable once, then delegates to the argument iterator.
    fn next(&mut self) -> Option<Self::Item> {
        self.program.take().or_else(|| self.arguments.next())
    }

    /// Includes the pending executable in the delegated iterator bounds.
    fn size_hint(&self) -> (usize, Option<usize>) {
        let program_len = usize::from(self.program.is_some());
        let (lower, upper) = self.arguments.size_hint();
        (
            lower.saturating_add(program_len),
            upper.and_then(|value| value.checked_add(program_len)),
        )
    }
}

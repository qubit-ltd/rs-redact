// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Process command iteration preserving the argument size hint.

use crate::formats::argv::ArgvItem;

/// Streams a process executable followed by caller-provided arguments.
///
/// Owns the argument iterator without collecting its items or copying argument
/// values. The executable is yielded once before the underlying iterator
/// advances.
///
/// # Type Parameters
///
/// * `'arguments` - Lifetime of the borrowed operating-system argument values.
/// * `I` - Owned argument source; iteration requires an iterator yielding
///   `ArgvItem<'arguments>` values.
pub(super) struct CommandItems<'arguments, I> {
    /// Executable returned before caller-provided arguments.
    program: Option<ArgvItem<'arguments>>,
    /// Remaining command-line arguments.
    arguments: I,
}

impl<'arguments, I> CommandItems<'arguments, I> {
    /// Creates an iterator whose executable is the first argv item.
    ///
    /// # Parameters
    ///
    /// * `program` - Borrowed executable item to yield first.
    /// * `arguments` - Argument source moved into the wrapper without advancing
    ///   it.
    ///
    /// # Returns
    ///
    /// A wrapper with the executable pending and the argument source unchanged.
    #[must_use]
    #[inline]
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
    ///
    /// # Returns
    ///
    /// `Some(item)` for the pending executable or the next underlying argument;
    /// `None` when the underlying iterator returns `None` after the executable.
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.program.take().or_else(|| self.arguments.next())
    }

    /// Includes the pending executable in the delegated iterator bounds.
    ///
    /// # Returns
    ///
    /// The lower bound, increased with saturation, and `Some(upper)` when the
    /// underlying upper bound exists and the addition does not overflow.
    /// The upper bound is `None` otherwise.
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let program_len = usize::from(self.program.is_some());
        let (lower, upper) = self.arguments.size_hint();
        (
            lower.saturating_add(program_len),
            upper.and_then(|value| value.checked_add(program_len)),
        )
    }
}

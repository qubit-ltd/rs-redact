// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazily admitted process environment-pair iteration.

use std::ffi::OsStr;
use std::marker::PhantomData;

use crate::formats::env::admission::admit_environment_name;
use crate::runtime::BatchSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Admits environment pairs before the renderer can inspect them.
///
/// # Type Parameters
///
/// * `'session` - Exclusive borrow of the batch transaction used for admission.
/// * `'variables` - Lifetime of the borrowed environment names and values.
/// * `I` - Lazily consumed source iterator; iteration requires items of type
///   `(&'variables OsStr, &'variables OsStr)`.
pub(super) struct AdmittedEnvironmentPairs<'session, 'variables, I> {
    /// Batch transaction charged before each pair is yielded.
    pub(super) session: &'session mut BatchSession,
    /// Remaining caller-provided environment pairs consumed lazily.
    pub(super) variables: I,
    /// Whether admission stopped the iterator before source exhaustion.
    pub(super) failed: bool,
    /// Borrow lifetime retained independently of the iterator's concrete type.
    pub(super) marker: PhantomData<&'variables ()>,
}

impl<'variables, I> Iterator for AdmittedEnvironmentPairs<'_, 'variables, I>
where
    I: Iterator<Item = (&'variables OsStr, &'variables OsStr)>,
{
    /// One admitted operating-system name and value pair.
    type Item = (&'variables OsStr, &'variables OsStr);

    /// Admits and returns the next pair without observing later input.
    ///
    /// # Returns
    ///
    /// `Some((name, value))` after all admission checks succeed; `None` when
    /// the source is exhausted or admission fails. Admission failure also
    /// sets `failed` and may consume the current pair, but never later
    /// pairs.
    fn next(&mut self) -> Option<Self::Item> {
        if self.variables.size_hint().1 == Some(0) {
            return None;
        }
        if !self.session.preflight_format_item(2) {
            self.failed = true;
            return None;
        }
        let (name, value) = self.variables.next()?;
        if !self.session.admit_format_collection_item()
            || !self.session.admit_format_node(2)
            || !admit_environment_name(self.session, name)
        {
            self.failed = true;
            return None;
        }
        if !self.session.admit_input(
            name.as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len()),
        ) {
            self.failed = true;
            return None;
        }
        Some((name, value))
    }
}

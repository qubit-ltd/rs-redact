// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazily admitted process environment-pair iteration.

use std::ffi::OsStr;

use crate::RedactionSession;

/// Admits environment pairs before the renderer can inspect them.
pub(super) struct AdmittedEnvironmentPairs<'session, 'variables, I> {
    pub(super) session: &'session mut RedactionSession,
    pub(super) variables: I,
    pub(super) failed: bool,
    pub(super) marker: std::marker::PhantomData<&'variables ()>,
}

impl<'variables, I> Iterator for AdmittedEnvironmentPairs<'_, 'variables, I>
where
    I: Iterator<Item = (&'variables OsStr, &'variables OsStr)>,
{
    type Item = (&'variables OsStr, &'variables OsStr);

    fn next(&mut self) -> Option<Self::Item> {
        if self.variables.size_hint().1 == Some(0) {
            return None;
        }
        if !self.session.preflight_format_item(2) {
            self.failed = true;
            return None;
        }
        let (name, value) = self.variables.next()?;
        if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
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

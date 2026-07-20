// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Destructive redaction contract for string-valued map-like containers.

use crate::{
    RedactionPolicy,
    Redactor,
};

/// Redacts map values in place after classifying each value by its runtime key.
pub trait RedactMapValueMut {
    /// Replaces sensitive values according to `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy used to classify every runtime key.
    fn redact_map_in_place(&mut self, policy: &RedactionPolicy);
}

impl<M: ?Sized> RedactMapValueMut for M
where
    for<'a> &'a mut M: IntoIterator<Item = (&'a String, &'a mut String)>,
{
    #[inline]
    fn redact_map_in_place(&mut self, policy: &RedactionPolicy) {
        Redactor::new(policy.clone()).redact_map_in_place(self);
    }
}

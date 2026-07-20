// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Formatting contract for string-valued map-like containers.

use std::fmt::{
    self,
    Formatter,
};

use crate::{
    RedactionPolicy,
    Redactor,
};

/// Formats map values after classifying each value by its runtime key.
pub trait RedactMapValue {
    /// Writes a lazy redacted map representation.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete policy used to classify every runtime key.
    /// * `formatter` - Destination debug formatter.
    ///
    /// # Returns
    ///
    /// The formatter result for the complete map.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination cannot accept the complete
    /// representation.
    #[doc(hidden)]
    fn fmt_redacted_map(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}

impl<M: ?Sized> RedactMapValue for M
where
    for<'a> &'a M: IntoIterator<Item = (&'a String, &'a String)>,
{
    #[inline]
    fn fmt_redacted_map(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        let redactor = Redactor::new(policy.clone());
        let mut map = formatter.debug_map();
        for (key, value) in self {
            let redacted = redactor.redact(key, value);
            map.entry(key, &redacted.as_str());
        }
        map.finish()
    }
}

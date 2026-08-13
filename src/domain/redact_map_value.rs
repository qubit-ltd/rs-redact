// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Formatting contract for text-valued map-like containers.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;

use crate::RedactValue;
use crate::RedactionSession;
use crate::policy::ResolvedField;

/// Formats map values after classifying each value by its runtime key.
///
/// # Type Parameters
///
/// * `K` - Runtime map-key type used for field classification.
/// * `V` - Map-value type formatted through redaction.
pub trait RedactMapValue<K: ?Sized, V: ?Sized> {
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
        session: &RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}

impl<M: ?Sized, K: ?Sized, V: ?Sized> RedactMapValue<K, V> for M
where
    for<'a> &'a M: IntoIterator<Item = (&'a K, &'a V)>,
    K: AsRef<str> + Debug,
    V: RedactValue + Debug,
{
    /// Formats every entry through the map redaction contract.
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
    /// Returns [`fmt::Error`] when the destination rejects an entry or the
    /// completed map.
    #[inline]
    fn fmt_redacted_map(
        &self,
        session: &RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        let policy = session.policy();
        let mut map = formatter.debug_map();
        for (key, value) in self {
            let resolved = policy.resolve_field(key.as_ref());
            match resolved {
                ResolvedField::Sensitive { sensitivity } => {
                    let redacted = value.redact_value(sensitivity, policy.masking());
                    map.entry(&key, &redacted);
                }
                ResolvedField::PassThrough => {
                    map.entry(&key, &value);
                }
            }
        }
        map.finish()
    }
}

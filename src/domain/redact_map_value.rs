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
use crate::domain::internal::debug_output_exhausted;
use crate::domain::internal::mask_byte_limit;
use crate::domain::redacted::complete_debug;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;
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
        session: &mut RedactionSession<'_>,
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
        session: &mut RedactionSession<'_>,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result {
        let alternate = formatter.alternate();
        let mut map = formatter.debug_map();
        let mut entries = self.into_iter();
        loop {
            if session.is_exhausted() || debug_output_exhausted() {
                break;
            }
            let Some((key, value)) = entries.next() else {
                break;
            };
            let key = key.as_ref();
            let session_limit = session.remaining_output_bytes();
            let domain_limit = mask_byte_limit().unwrap_or(usize::MAX);
            let admission = if session.input_is_precharged() {
                session.admit_precharged_output(domain_limit)
            } else {
                let input_bytes = key
                    .len()
                    .saturating_add(RedactValue::redaction_input_bytes(value));
                session.admit(input_bytes, domain_limit, 0)
            };
            let RedactionAdmission::Render { max_output_bytes } = admission else {
                break;
            };
            let resolved = session.policy().resolve_field(key);
            let completed = match resolved {
                ResolvedField::Sensitive { sensitivity } => {
                    let redacted = value.redact_value(sensitivity, session.policy().masking());
                    complete_debug(&redacted, max_output_bytes, alternate)
                }
                ResolvedField::PassThrough => complete_debug(&value, max_output_bytes, alternate),
            };
            let completion = if completed.truncated() {
                if domain_limit < session_limit {
                    FragmentCompletion::DomainTruncated
                } else {
                    FragmentCompletion::SessionTruncated
                }
            } else {
                FragmentCompletion::Complete
            };
            let truncated = completed.truncated();
            session.commit_output(completed.len(), completion);
            map.entry(&key, &completed);
            if truncated || session.is_exhausted() || debug_output_exhausted() {
                break;
            }
        }
        map.finish()
    }
}

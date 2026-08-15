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
use crate::domain::DomainTruncated;
use crate::domain::internal::debug_output_exhausted;
use crate::domain::internal::mask_byte_limit;
use crate::domain::redacted::complete_debug;
use crate::policy::DomainTraversalAdmission;
use crate::policy::DomainValueAdmission;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;
use crate::policy::ResolvedField;

/// Formats map values after classifying each value by its runtime key.
///
/// The blanket implementation accepts borrowed map-like containers only when
/// their iterator implements [`ExactSizeIterator`]. Exact remaining length is
/// the non-consuming EOF proof that prevents both phantom collection charges
/// and pulling an unadmitted entry. Custom implementations of this trait are
/// responsible for providing an equally sound traversal contract.
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
    /// * `session` - Shared policy and budget used for every runtime key.
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
    for<'a> &'a M:
        IntoIterator<Item = (&'a K, &'a V), IntoIter: ExactSizeIterator>,
    K: AsRef<str> + Debug,
    V: RedactValue + Debug,
{
    /// Formats every entry through the map redaction contract.
    ///
    /// The map charges its domain-value node once. The blanket implementation
    /// requires an [`ExactSizeIterator`] so `len() == 0` proves exhaustion
    /// without consuming an entry; otherwise the map charges each collection
    /// item before calling `next`. Limit exhaustion therefore writes one
    /// unquoted marker and stops without pulling an unadmitted key or value.
    /// Admitted values are classified and completed under an output-only frame;
    /// exact value bytes are committed immediately, while the enclosing map
    /// frame later charges keys and punctuation without double-charging nested
    /// output. Pure map formatting does not consume diagnostic input bytes.
    ///
    /// # Parameters
    ///
    /// * `session` - Shared policy and budget used for every runtime key.
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
        let DomainValueAdmission::Entered(mut scope) =
            session.enter_domain_value()
        else {
            return Debug::fmt(&DomainTruncated, formatter);
        };
        let mut map = formatter.debug_map();
        let mut entries = self.into_iter();
        loop {
            if scope.session().is_exhausted() || debug_output_exhausted() {
                break;
            }
            if entries.len() == 0 {
                break;
            }
            if scope.admit_collection_item()
                == DomainTraversalAdmission::LimitReached
            {
                map.entry(&DomainTruncated, &DomainTruncated);
                break;
            }
            let Some((key, value)) = entries.next() else {
                break;
            };
            let key = key.as_ref();
            let session_limit = scope.session().remaining_output_bytes();
            let domain_limit = mask_byte_limit().unwrap_or(usize::MAX);
            let admission = scope.session().admit_output_only(domain_limit);
            let max_output_bytes = match admission {
                RedactionAdmission::Render { max_output_bytes } => {
                    max_output_bytes
                }
                RedactionAdmission::Fallback => unreachable!(
                    "output-only domain admission cannot reject input"
                ),
                RedactionAdmission::Exhausted => break,
            };
            let resolved = scope.session().policy().resolve_field(key);
            let completed = match resolved {
                ResolvedField::Sensitive { sensitivity } => {
                    let redacted = value.redact_value(
                        sensitivity,
                        scope.session().policy().masking(),
                    );
                    complete_debug(&redacted, max_output_bytes, alternate)
                }
                ResolvedField::PassThrough => {
                    complete_debug(&value, max_output_bytes, alternate)
                }
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
            scope.session().commit_output(completed.len(), completion);
            map.entry(&key, &completed);
            if truncated
                || scope.session().is_exhausted()
                || debug_output_exhausted()
            {
                break;
            }
        }
        map.finish()
    }
}

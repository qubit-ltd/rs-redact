// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Formatting contract for text-valued map-like containers.

use std::fmt::Debug;

use crate::domain::RedactValue;
use crate::domain::RedactionWriter;
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
    /// Writes this map directly into an active structured writer.
    ///
    /// This is the transaction-aware map path used by [`RedactionWriter`]. It
    /// must use the supplied writer for every key classification, traversal
    /// admission, and byte budget; it must not create a new session or a lazy
    /// rendering result.
    #[doc(hidden)]
    fn write_redacted_map_to(&self, writer: &mut RedactionWriter<'_>);
}

impl<M: ?Sized, K: ?Sized, V: ?Sized> RedactMapValue<K, V> for M
where
    for<'a> &'a M: IntoIterator<Item = (&'a K, &'a V), IntoIter: ExactSizeIterator>,
    K: AsRef<str> + Debug,
    V: RedactValue + Debug,
{
    fn write_redacted_map_to(&self, writer: &mut RedactionWriter<'_>) {
        if !writer.begin_nested_value() {
            writer.literal("<truncated>");
            return;
        }
        writer.literal("{");
        let mut entries = self.into_iter();
        loop {
            if writer.is_truncated() {
                break;
            }
            if entries.len() == 0 {
                break;
            }
            if !writer.admit_nested_collection_item() {
                writer.literal("<truncated>");
                break;
            }
            let Some((key, value)) = entries.next() else {
                break;
            };
            let key = key.as_ref();
            writer.write_debug(key);
            writer.literal(": ");
            match writer.policy().resolve_field(key) {
                ResolvedField::Sensitive { sensitivity } => {
                    let rendered = value.redact_value(sensitivity, writer.policy().masking());
                    writer.write_debug(&rendered);
                }
                ResolvedField::PassThrough => writer.write_debug(value),
            }
            writer.literal(", ");
        }
        writer.trim_trailing_separator();
        writer.literal("}");
        writer.finish_nested_value();
    }
}

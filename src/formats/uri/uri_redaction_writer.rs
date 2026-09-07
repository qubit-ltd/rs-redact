// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URI operations backed by one mutable diagnostic session.

use super::redaction::redact_uri_with_limit;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// URI facade borrowing one diagnostic session.
///
/// # Type Parameters
///
/// * `'session` - Borrow of the parent composer's unpublished transaction.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::standard().text_composer().uri(|uri| {
///     uri.value("https://example.test/?password=raw-secret");
/// }).finish();
/// assert!(!output.text().as_str().contains("raw-secret"));
/// ```
pub struct UriRedactionWriter<'session> {
    /// Text transaction that owns policy, accounting, and aggregate output.
    session: &'session mut TextSession,
}

impl<'session> UriRedactionWriter<'session> {
    /// Creates a URI facade borrowing a parent session.
    ///
    /// # Parameters
    ///
    /// * `session` - Parent transaction receiving admitted URI output.
    ///
    /// # Returns
    ///
    /// A writer borrowing the existing policy and resource ledger.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts a URI into the parent session's aggregate output.
    ///
    /// # Parameters
    ///
    /// * `value` - URI text whose identity, path, query, and fragment follow
    ///   the parent policy after shared input and structural admission.
    ///
    /// # Returns
    ///
    /// This writer for further operations; malformed or rejected input is
    /// represented by safe output and the parent's diagnostic summary.
    pub fn value(&mut self, value: &str) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let input_was_empty = value.is_empty();
        let value = self.session.admit_input_prefix(value);
        if value.is_empty() && !input_was_empty {
            return self;
        }
        if !self.admit_uri_structure(value) {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish(),
            );
            return self;
        }
        let result = self.redact_uri_direct(value);
        self.session.append_rendered_operation(result);
        self
    }
}

impl UriRedactionWriter<'_> {
    /// Renders an already admitted URI within the transaction's remaining
    /// bytes.
    ///
    /// The caller checks output closure and admits input and structure first.
    /// The returned operation retains output-rejection facts so publication
    /// closes later work even when a UTF-8 boundary leaves spare bytes.
    ///
    /// # Parameters
    ///
    /// * `input` - URI text already admitted by the parent transaction.
    ///
    /// # Returns
    ///
    /// Unpublished safe text and completion facts for parent publication.
    #[must_use]
    pub(crate) fn redact_uri_direct(&mut self, input: &str) -> RenderedOperation {
        redact_uri_with_limit(self.session.policy(), input, self.session.remaining_output_bytes())
    }

    /// Charges URI root and query-pair structure before the URI renderer
    /// decodes individual components. The raw query scan stops at the first
    /// rejected pair, so a later suffix cannot be rendered.
    ///
    /// # Parameters
    ///
    /// * `input` - Admitted URI text to scan for raw query separators.
    ///
    /// # Returns
    ///
    /// Whether all root and query-pair charges fit the shared budget.
    #[must_use]
    #[inline(always)]
    fn admit_uri_structure(&mut self, input: &str) -> bool {
        admit_uri_structure(self.session, input)
    }
}

/// Charges URI root and query-pair structure without parsing component values.
///
/// # Parameters
///
/// * `session` - Parent transaction charged incrementally during the scan.
/// * `input` - Admitted URI text, with query separators counted before
///   decoding.
///
/// # Returns
///
/// `true` when all structural charges fit; `false` after the first rejection,
/// which is retained in the parent summary without scanning later pairs.
#[must_use]
pub(crate) fn admit_uri_structure(session: &mut dyn RuntimeSession, input: &str) -> bool {
    if !session.admit_format_node(1) {
        return false;
    }
    let without_fragment = input.split_once('#').map_or(input, |(prefix, _)| prefix);
    let Some((_, query)) = without_fragment.split_once('?') else {
        return true;
    };
    for _ in query.split('&') {
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::redact_uri_with_limit;
    use crate::RedactionCompletion;
    use crate::RedactionPolicy;

    /// Verifies URI rendering receives the transaction's remaining output
    /// allowance and never creates a second unbounded output path.
    #[test]
    fn test_bounded_uri_helper_never_exceeds_the_caller_allowance() {
        let output = redact_uri_with_limit(
            &RedactionPolicy::standard(),
            "https://example.test/a/very/long/path?token=secret",
            16,
        );

        assert_eq!(output.completion(), RedactionCompletion::Truncated);
        assert!(output.reasons().contains(crate::RedactionReason::OutputLimitReached));
        assert!(output.text().len() <= 16);
    }
}

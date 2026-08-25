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
pub struct UriRedactionWriter<'session> {
    /// Text transaction that owns policy, accounting, and aggregate output.
    session: &'session mut TextSession,
}

impl<'session> UriRedactionWriter<'session> {
    /// Creates a URI facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts a URI into the parent session's aggregate output.
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
    /// Redacts one URI while charging the shared input and output budgets.
    ///
    /// Input is admitted before parsing. If the session has no output left,
    /// this method returns an empty fail-closed result without inspecting the
    /// URI. A component-level output limit can truncate this result while the
    /// session remains usable; exhaustion of the shared output budget closes
    /// the session for later operations. The returned completion is `Complete`
    /// for a full safe rewrite, `Truncated` for non-empty fallback or omitted
    /// output, and `Exhausted` only when the safe text is empty. Existing URI
    /// status is represented solely by the transaction's common summary.
    #[must_use]
    pub(crate) fn redact_uri_direct(&mut self, input: &str) -> RenderedOperation {
        redact_uri_with_limit(self.session.policy(), input, self.session.remaining_output_bytes())
    }

    /// Charges URI root and query-pair structure before the URI renderer
    /// decodes individual components. The raw query scan stops at the first
    /// rejected pair, so a later suffix cannot be rendered.
    fn admit_uri_structure(&mut self, input: &str) -> bool {
        admit_uri_structure(self.session, input)
    }
}

/// Charges URI root and query-pair structure without parsing component values.
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
    use crate::Redactor;

    /// Verifies URI rendering receives the transaction's remaining output
    /// allowance and never creates a second unbounded output path.
    #[test]
    fn bounded_uri_helper_never_exceeds_the_caller_allowance() {
        let output = redact_uri_with_limit(
            &RedactionPolicy::standard(),
            "https://example.test/a/very/long/path?token=secret",
            16,
        );

        assert_eq!(output.completion(), RedactionCompletion::Truncated);
        assert!(output.reasons().contains(crate::RedactionReason::OutputLimitReached));
        assert!(output.text().len() <= 16);
    }

    /// Verifies a URI adapter receives the output allowance left after earlier
    /// aggregate writes in its enclosing transaction.
    #[test]
    fn uri_session_uses_the_transaction_remaining_output_allowance() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                let _ = limits.max_output_bytes(20);
            })
            .expect("the test limit draft should build")
            .build()
            .expect("the test policy should build");
        let output = Redactor::new(policy)
            .text_composer()
            .literal("prefix")
            .uri(|uri| {
                uri.value("https://example.test/a/very/long/path?token=secret");
            })
            .finish();

        assert_eq!(output.text().as_str(), "prefixhtt<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert_eq!(output.summary().usage().output_bytes(), 20);
    }
}

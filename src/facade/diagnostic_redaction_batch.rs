// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Independently resolvable redaction items owned by one batch transaction.

use std::ffi::OsStr;
use std::fmt::Display;

#[cfg(feature = "http")]
use http::HeaderMap;
#[cfg(feature = "http")]
use http::HeaderValue;
#[cfg(feature = "json")]
use serde_json::Value;

use super::DiagnosticRedactionBatchOutput;
use super::DiagnosticRedactionHandle;
use super::DiagnosticRedactionOutput;
use crate::domain::Redact;
#[cfg(feature = "http")]
use crate::formats::http::BodyCapture;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;

/// Escaped at publication when callers choose the default diagnostic finish.
const DEFAULT_DIAGNOSTIC_MARKER: &str = "<redaction incomplete>";

/// Accumulates independently resolvable redaction items under one budget.
///
/// Each operation returns an opaque handle. Handles are usable only with the
/// [`DiagnosticRedactionOutput`] produced by consuming this batch with
/// [`Self::finish_with_marker`].
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let mut batch = Redactor::strict().diagnostic_batch();
/// let handle = batch.redact_field("password", "raw-secret");
/// let output = batch.finish_with_marker("<redaction incomplete>");
/// assert!(!output.text(handle).as_str().contains("raw-secret"));
/// ```
pub struct DiagnosticRedactionBatch {
    /// Typed transaction that owns unpublished independently resolvable items.
    session: BatchSession,
}

impl DiagnosticRedactionBatch {
    /// Creates a batch backed by one private runtime transaction.
    ///
    /// # Parameters
    ///
    /// - `session`: Fresh batch transaction exclusively owned by this facade.
    ///
    /// # Returns
    ///
    /// A batch retaining the transaction’s policy and shared budget.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn from_session(session: BatchSession) -> Self {
        Self { session }
    }

    /// Converts the runtime-private handle into its public batch counterpart.
    ///
    /// # Parameters
    ///
    /// - `handle`: Runtime capability retaining its transaction identity and
    ///   item index.
    ///
    /// # Returns
    ///
    /// The equivalent public opaque handle without changing identity.
    #[must_use]
    #[inline(always)]
    fn wrap(handle: RedactionHandle) -> DiagnosticRedactionHandle {
        let (batch_id, item_index) = handle.parts();
        DiagnosticRedactionHandle { batch_id, item_index }
    }

    /// Returns whether the shared output budget has closed this batch.
    ///
    /// # Returns
    ///
    /// True after the shared output boundary closes; later item operations
    /// cannot reopen it.
    #[must_use]
    #[inline(always)]
    pub fn is_output_exhausted(&self) -> bool {
        self.session.is_output_exhausted()
    }

    /// Redacts one named scalar field and returns its opaque batch handle.
    ///
    /// `field` selects the policy rule applied to `value`. The result remains
    /// unpublished until [`Self::finish_with_marker`] consumes this batch.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Lazily evaluated scalar formatter.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw key admitted before classification and value access.
    /// - `value`: Scalar formatter evaluated only when admission and masking
    ///   require it.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[must_use]
    #[inline(always)]
    pub fn redact_field<T>(&mut self, field: &str, value: &T) -> DiagnosticRedactionHandle
    where
        T: Display + ?Sized,
    {
        let handle = self.session.redact_field(field, value);
        let (batch_id, item_index) = handle.parts();
        DiagnosticRedactionHandle { batch_id, item_index }
    }

    /// Redacts one domain value and returns its opaque batch handle.
    ///
    /// `value` is rendered only through its [`Redact`] implementation; the
    /// result remains unpublished until
    /// [`Self::finish_with_marker`] consumes this batch.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Domain type exposing structured redaction.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed domain value visited through structured redaction.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[must_use]
    #[inline(always)]
    pub fn redact_value<T>(&mut self, value: &T) -> DiagnosticRedactionHandle
    where
        T: Redact + ?Sized,
    {
        let handle = self.session.redact_value(value);
        let (batch_id, item_index) = handle.parts();
        DiagnosticRedactionHandle { batch_id, item_index }
    }

    /// Redacts an explicitly classified argv sequence as one item.
    ///
    /// The finite `items` iterator is admitted under this batch's shared
    /// resource budget before its values are inspected.
    ///
    /// # Type Parameters
    ///
    /// - `'items`: Lifetime of borrowed argument contents.
    /// - `I`: One-pass iterator of argument items.
    ///
    /// # Parameters
    ///
    /// - `items`: Argument items visited once in source order.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[must_use]
    #[inline(always)]
    pub fn redact_argv<'items, I>(&mut self, items: I) -> DiagnosticRedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        Self::wrap(self.session.redact_argv(items))
    }

    /// Redacts an argv sequence with heuristic option classification as one
    /// item.
    ///
    /// The finite `items` iterator is admitted under this batch's shared
    /// resource budget before its values are inspected.
    ///
    /// # Type Parameters
    ///
    /// - `'items`: Lifetime of borrowed argument contents.
    /// - `I`: One-pass iterator of argument items.
    ///
    /// # Parameters
    ///
    /// - `items`: Argument items visited once in source order.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[must_use]
    #[inline(always)]
    pub fn redact_heuristic_argv<'items, I>(&mut self, items: I) -> DiagnosticRedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        Self::wrap(self.session.redact_heuristic_argv(items))
    }

    /// Redacts one environment assignment as one item.
    ///
    /// `name` selects the environment rule applied to `value`.
    ///
    /// # Parameters
    ///
    /// - `name`: Environment name selecting the classification rule.
    /// - `value`: Environment value admitted and transformed within the shared
    ///   budget.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[must_use]
    #[inline(always)]
    pub fn redact_env(&mut self, name: &str, value: &str) -> DiagnosticRedactionHandle {
        Self::wrap(self.session.redact_env(name, value))
    }

    /// Redacts environment assignments as one item.
    ///
    /// The finite `pairs` iterator is admitted before the renderer observes
    /// later entries.
    ///
    /// # Type Parameters
    ///
    /// - `'items`: Lifetime of borrowed names and values.
    /// - `I`: One-pass iterator of environment assignments.
    ///
    /// # Parameters
    ///
    /// - `pairs`: Native environment names and values visited once in source
    ///   order.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[must_use]
    #[inline(always)]
    pub fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> DiagnosticRedactionHandle
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        Self::wrap(self.session.redact_env_pairs(pairs))
    }

    /// Redacts one process command as one item.
    ///
    /// `program` precedes `arguments`; `variables` are rendered after argv
    /// when the shared budget still admits them.
    ///
    /// # Type Parameters
    ///
    /// - `'arguments`: Borrow of the executable and arguments.
    /// - `'variables`: Borrow of environment names and values.
    /// - `A`: One-pass iterator of arguments.
    /// - `E`: One-pass iterator of environment assignments.
    ///
    /// # Parameters
    ///
    /// - `program`: Native executable name preceding the arguments.
    /// - `arguments`: Arguments visited once in command order.
    /// - `variables`: Environment assignments visited after argv when admission
    ///   remains open.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[must_use]
    #[inline(always)]
    pub fn redact_process<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> DiagnosticRedactionHandle
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        Self::wrap(self.session.redact_process(program, arguments, variables))
    }

    /// Redacts one JSON document as one item.
    ///
    /// Invalid JSON produces a safe result carrying `InvalidJson` provenance.
    ///
    /// # Parameters
    ///
    /// - `text`: Raw JSON document admitted and parsed within the shared
    ///   budget.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub fn redact_json(&mut self, text: &str) -> DiagnosticRedactionHandle {
        Self::wrap(self.session.redact_json(text))
    }

    /// Redacts a borrowed parsed JSON value without taking ownership of it.
    ///
    /// # Parameters
    ///
    /// - `value`: Parsed JSON value borrowed for admission and transformation.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub fn redact_json_value(&mut self, value: &Value) -> DiagnosticRedactionHandle {
        Self::wrap(self.session.redact_json_value(value))
    }

    /// Redacts one HTTP URL as one item.
    ///
    /// Invalid URLs produce a safe result carrying `InvalidUri` provenance.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw HTTP URL admitted before parsing.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub fn redact_http_url(&mut self, value: &str) -> DiagnosticRedactionHandle {
        Self::wrap(self.session.redact_http_url(value))
    }

    /// Redacts one HTTP header map as one item.
    ///
    /// # Parameters
    ///
    /// - `headers`: Header collection including repeated values.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub fn redact_http_headers(&mut self, headers: &HeaderMap) -> DiagnosticRedactionHandle {
        Self::wrap(self.session.redact_http_headers(headers))
    }

    /// Redacts one captured HTTP body as one item using optional parsed
    /// content-type metadata.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured bytes with their completeness metadata.
    /// - `content_type`: Optional media type; None preserves missing-type
    ///   policy behavior.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub fn redact_http_body(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> DiagnosticRedactionHandle {
        Self::wrap(self.session.redact_http_body(capture, content_type))
    }

    /// Redacts one captured HTTP body using optional textual content-type
    /// metadata.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured bytes with their completeness metadata.
    /// - `content_type`: Optional media type; None preserves missing-type
    ///   policy behavior.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub fn redact_http_body_with_content_type_text(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> DiagnosticRedactionHandle {
        Self::wrap(
            self.session
                .redact_http_body_with_content_type_text(capture, content_type),
        )
    }

    /// Redacts one URI as one item.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw URI admitted before parsing.
    ///
    /// # Returns
    ///
    /// An opaque handle to the recorded item, resolvable after this batch is
    /// finished.
    #[cfg(feature = "uri")]
    #[must_use]
    #[inline(always)]
    pub fn redact_uri(&mut self, value: &str) -> DiagnosticRedactionHandle {
        Self::wrap(self.session.redact_uri(value))
    }

    /// Consumes the batch and prepares fail-closed diagnostic presentation.
    ///
    /// Complete items retain their redacted text. Incomplete items and invalid
    /// handles resolve to the escaped `marker` without returning an error.
    ///
    /// # Parameters
    ///
    /// - `marker`: Caller-selected fallback escaped once outside the batch’s
    ///   output budget.
    ///
    /// # Returns
    ///
    /// A diagnostic publication resolving complete items to their text and all
    /// others to the marker.
    #[must_use]
    #[inline(always)]
    pub fn finish_with_marker(self, marker: &str) -> DiagnosticRedactionOutput {
        DiagnosticRedactionOutput::new(self.finish_publication(), marker)
    }

    /// Consumes the batch and publishes fail-closed diagnostics using the
    /// standard incomplete-redaction marker.
    #[must_use]
    #[inline(always)]
    pub fn finish(self) -> DiagnosticRedactionOutput {
        self.finish_with_marker(DEFAULT_DIAGNOSTIC_MARKER)
    }

    /// Consumes the batch and publishes its item results and summary.
    ///
    /// # Returns
    ///
    /// The crate-private publication owning all recorded items and aggregate
    /// accounting.
    #[must_use]
    #[inline(always)]
    pub(crate) fn finish_publication(self) -> DiagnosticRedactionBatchOutput {
        DiagnosticRedactionBatchOutput::from_publication(self.session.finish())
    }
}

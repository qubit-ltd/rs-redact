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

use super::RedactionBatchDiagnostics;
use super::RedactionBatchHandle;
use super::RedactionBatchOutput;
use crate::domain::Redact;
#[cfg(feature = "http")]
use crate::formats::http::BodyCapture;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;

/// Accumulates independently resolvable redaction items under one budget.
///
/// Each operation returns an opaque handle. Handles are usable only with the
/// [`RedactionBatchDiagnostics`] produced by consuming this batch with
/// [`Self::finish_for_diagnostics`].
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let mut batch = Redactor::strict().batch();
/// let handle = batch.redact_field("password", "raw-secret");
/// let output = batch.finish_for_diagnostics("<redaction incomplete>");
/// assert!(!output.text(handle).as_str().contains("raw-secret"));
/// ```
pub struct RedactionBatch {
    /// Typed transaction that owns unpublished independently resolvable items.
    session: BatchSession,
}

impl RedactionBatch {
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
    fn wrap(handle: RedactionHandle) -> RedactionBatchHandle {
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
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
    /// unpublished until [`Self::finish_for_diagnostics`] consumes this batch.
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
    pub fn redact_field<T>(&mut self, field: &str, value: &T) -> RedactionBatchHandle
    where
        T: Display + ?Sized,
    {
        let handle = self.session.redact_field(field, value);
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
    }

    /// Redacts one domain value and returns its opaque batch handle.
    ///
    /// `value` is rendered only through its [`Redact`] implementation; the
    /// result remains unpublished until
    /// [`Self::finish_for_diagnostics`] consumes this batch.
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
    pub fn redact_value<T>(&mut self, value: &T) -> RedactionBatchHandle
    where
        T: Redact + ?Sized,
    {
        let handle = self.session.redact_value(value);
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
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
    pub fn redact_argv<'items, I>(&mut self, items: I) -> RedactionBatchHandle
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
    pub fn redact_heuristic_argv<'items, I>(&mut self, items: I) -> RedactionBatchHandle
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
    pub fn redact_env(&mut self, name: &str, value: &str) -> RedactionBatchHandle {
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
    pub fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> RedactionBatchHandle
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
    ) -> RedactionBatchHandle
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
    pub fn redact_json(&mut self, text: &str) -> RedactionBatchHandle {
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
    pub fn redact_json_value(&mut self, value: &Value) -> RedactionBatchHandle {
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
    pub fn redact_http_url(&mut self, value: &str) -> RedactionBatchHandle {
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
    pub fn redact_http_headers(&mut self, headers: &HeaderMap) -> RedactionBatchHandle {
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
    ) -> RedactionBatchHandle {
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
    ) -> RedactionBatchHandle {
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
    pub fn redact_uri(&mut self, value: &str) -> RedactionBatchHandle {
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
    pub fn finish_for_diagnostics(self, marker: &str) -> RedactionBatchDiagnostics {
        RedactionBatchDiagnostics::new(self.finish(), marker)
    }

    /// Consumes the batch and publishes its item results and summary.
    ///
    /// # Returns
    ///
    /// The crate-private publication owning all recorded items and aggregate
    /// accounting.
    #[must_use]
    #[inline(always)]
    pub(crate) fn finish(self) -> RedactionBatchOutput {
        RedactionBatchOutput::from_publication(self.session.finish())
    }
}

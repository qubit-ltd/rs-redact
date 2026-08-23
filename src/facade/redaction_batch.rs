// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Independently resolvable redaction items owned by one batch transaction.

use super::RedactionBatchHandle;
use super::RedactionBatchOutput;
use crate::domain::Redact;
use crate::runtime::RedactionHandle;
use crate::runtime::RedactionSession;

/// Accumulates independently resolvable redaction items under one budget.
///
/// Each operation returns an opaque handle. Handles are usable only with the
/// [`RedactionBatchOutput`] produced by consuming this batch with
/// [`Self::finish`].
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let mut batch = Redactor::strict().batch();
/// let handle = batch.redact_field("password", "raw-secret");
/// let output = batch.finish();
/// let item = output.resolve(handle).expect("the batch owns the handle");
/// assert!(!item.text().as_str().contains("raw-secret"));
/// ```
pub struct RedactionBatch {
    session: RedactionSession,
}

impl RedactionBatch {
    /// Creates a batch backed by one private runtime transaction.
    #[must_use]
    pub(crate) const fn from_session(session: RedactionSession) -> Self {
        Self { session }
    }
    /// Redacts one named scalar field and returns its opaque batch handle.
    ///
    /// `field` selects the policy rule applied to `value`. The result remains
    /// unpublished until [`Self::finish`] consumes this batch.
    #[must_use]
    pub fn redact_field<T>(&mut self, field: &str, value: &T) -> RedactionBatchHandle
    where
        T: std::fmt::Display + ?Sized,
    {
        let handle = self.session.redact_field(field, value);
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
    }
    /// Redacts one domain value and returns its opaque batch handle.
    ///
    /// `value` is rendered only through its [`Redact`] implementation; the
    /// result remains unpublished until [`Self::finish`] consumes this batch.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn redact_heuristic_argv<'items, I>(&mut self, items: I) -> RedactionBatchHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        Self::wrap(self.session.redact_heuristic_argv(items))
    }
    /// Redacts one environment assignment as one item.
    ///
    /// `name` selects the environment rule applied to `value`.
    #[must_use]
    pub fn redact_env(&mut self, name: &str, value: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_env(name, value))
    }
    /// Redacts environment assignments as one item.
    ///
    /// The finite `pairs` iterator is admitted before the renderer observes
    /// later entries.
    #[must_use]
    pub fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> RedactionBatchHandle
    where
        I: IntoIterator<Item = (&'items std::ffi::OsStr, &'items std::ffi::OsStr)>,
    {
        Self::wrap(self.session.redact_env_pairs(pairs))
    }
    /// Redacts one process command as one item.
    ///
    /// `program` precedes `arguments`; `variables` are rendered after argv
    /// when the shared budget still admits them.
    #[must_use]
    pub fn redact_process<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments std::ffi::OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionBatchHandle
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables std::ffi::OsStr, &'variables std::ffi::OsStr)>,
    {
        Self::wrap(self.session.redact_process(program, arguments, variables))
    }
    /// Redacts one JSON document as one item.
    ///
    /// Invalid JSON produces a safe result carrying `InvalidJson` provenance.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn redact_json(&mut self, text: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_json(text))
    }

    /// Redacts a borrowed parsed JSON value without taking ownership of it.
    #[cfg(feature = "json")]
    pub fn redact_json_value(&mut self, value: &serde_json::Value) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_json_value(value))
    }
    /// Redacts one HTTP URL as one item.
    ///
    /// Invalid URLs produce a safe result carrying `InvalidUri` provenance.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_url(&mut self, value: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_http_url(value))
    }
    /// Redacts one HTTP header map as one item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_headers(&mut self, headers: &http::HeaderMap) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_http_headers(headers))
    }
    /// Redacts one captured HTTP body as one item using optional parsed
    /// content-type metadata.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_body(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_http_body(capture, content_type))
    }
    /// Redacts one captured HTTP body using optional textual content-type
    /// metadata.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_body_with_content_type_text(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionBatchHandle {
        Self::wrap(
            self.session
                .redact_http_body_with_content_type_text(capture, content_type),
        )
    }
    /// Redacts one URI as one item.
    #[cfg(feature = "uri")]
    #[must_use]
    pub fn redact_uri(&mut self, value: &str) -> RedactionBatchHandle {
        Self::wrap(self.session.redact_uri(value))
    }
    /// Consumes the batch and publishes its item results and summary.
    #[must_use]
    pub fn finish(self) -> RedactionBatchOutput {
        RedactionBatchOutput::from_publication(self.session.finish_batch())
    }

    /// Converts the runtime-private handle into its public batch counterpart.
    fn wrap(handle: RedactionHandle) -> RedactionBatchHandle {
        let (batch_id, item_index) = handle.parts();
        RedactionBatchHandle { batch_id, item_index }
    }
}

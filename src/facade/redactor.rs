// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateless redaction operations backed by an immutable policy.
// qubit-style: allow multiple-public-types

use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::PoisonError;

use crate::RedactedTextComposer;
use crate::RedactionBatch;
use crate::RedactionInspectionResult;
use crate::RedactionPolicy;
use crate::domain::Redact;
use crate::facade::RedactionTextOutput;
use crate::runtime::BatchSession;
use crate::runtime::InspectionSession;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Applies one immutable policy snapshot to supported diagnostic values.
///
/// Composers and batches created from a redactor retain this snapshot even if
/// the process-wide application default changes later.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::strict().redact_field("password", "raw-secret");
/// assert!(!output.text().as_str().contains("raw-secret"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redactor {
    /// Field classification and masking configuration.
    policy: Arc<RedactionPolicy>,
}

impl Redactor {
    /// Creates a redactor using `policy`.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable field classification and masking configuration.
    ///
    /// # Returns
    ///
    /// A redactor that owns the supplied policy snapshot.
    #[must_use]
    #[inline(always)]
    pub fn new(policy: RedactionPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    /// Creates a redactor from the immutable built-in standard policy.
    #[must_use]
    #[inline]
    pub fn standard() -> Self {
        Self::new(RedactionPolicy::standard())
    }

    /// Creates a redactor with the strict policy for untrusted scalar data.
    ///
    /// Unknown fields are masked at [`crate::Sensitivity::Secret`].
    #[must_use]
    #[inline]
    pub fn strict() -> Self {
        Self::new(RedactionPolicy::strict())
    }

    /// Returns a snapshot of the current application default redactor.
    ///
    /// The returned value is detached from the global slot. Later calls to
    /// [`Self::replace_application_default`] do not alter this redactor or
    /// composers and batches created from it.
    #[must_use]
    pub fn application_default() -> Self {
        match crate::facade::default_redactor::slot().read() {
            Ok(redactor) => redactor.clone(),
            Err(error) => PoisonError::into_inner(error).clone(),
        }
    }

    /// Atomically replaces the application default redactor.
    ///
    /// The replacement is linearizable: concurrent readers observe either the
    /// complete previous snapshot or the complete new snapshot. Existing
    /// redactors, composers, and batches keep their own snapshots. The previous
    /// default is returned so callers can restore it after a scoped change.
    #[must_use]
    pub fn replace_application_default(redactor: Self) -> Self {
        let mut current = match crate::facade::default_redactor::slot().write() {
            Ok(guard) => guard,
            Err(error) => PoisonError::into_inner(error),
        };
        std::mem::replace(&mut *current, redactor)
    }

    /// Redacts one domain value into final text and an execution summary.
    #[must_use]
    pub fn redact<T>(&self, value: &T) -> crate::RedactionTextOutput
    where
        T: Redact + ?Sized,
    {
        let mut batch = self.batch();
        let handle = batch.redact_value(value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one domain value without rendering any field content.
    ///
    /// # Errors
    ///
    /// Returns an inconclusive result when structural or input admission
    /// prevents the complete domain value from being classified.
    pub fn inspect<T>(&self, value: &T) -> RedactionInspectionResult
    where
        T: Redact + ?Sized,
    {
        let mut session = self.inspection_runtime();
        session.inspect(value);
        session.finish()
    }

    /// Returns the immutable policy used by this redactor.
    ///
    /// # Returns
    ///
    /// A borrowed view of the redactor's policy snapshot.
    #[must_use]
    #[inline(always)]
    pub fn policy(&self) -> &RedactionPolicy {
        self.policy.as_ref()
    }

    /// Creates private accounting for one text-composition operation.
    ///
    /// # Returns
    ///
    /// A private runtime owning a clone of this redactor's immutable policy
    /// snapshot.
    #[must_use]
    #[inline]
    pub(crate) fn text_runtime(&self) -> TextSession {
        TextSession::new(Arc::clone(&self.policy))
    }

    /// Creates the private runtime selected for independently resolvable items.
    #[must_use]
    pub(crate) fn batch_runtime(&self) -> BatchSession {
        BatchSession::new(Arc::clone(&self.policy))
    }

    /// Creates private accounting for one non-rendering inspection.
    #[must_use]
    pub(crate) fn inspection_runtime(&self) -> InspectionSession {
        InspectionSession::new(Arc::clone(&self.policy))
    }

    /// Starts one ordered text-composition transaction.
    ///
    /// The returned composer owns a fresh budget ledger initialized from this
    /// redactor's immutable policy snapshot. Its consuming `finish` method
    /// publishes one [`RedactionTextOutput`].
    ///
    /// # Returns
    ///
    /// A composer for one independently bounded ordered text result.
    #[must_use]
    pub fn text_composer(&self) -> RedactedTextComposer {
        RedactedTextComposer::from_session(self.text_runtime())
    }

    /// Starts one batch of independently resolvable redaction items.
    ///
    /// The returned batch owns a fresh budget ledger initialized from this
    /// redactor's immutable policy snapshot. Its consuming `finish` method
    /// publishes a [`crate::RedactionBatchOutput`].
    ///
    /// # Returns
    /// A mutable batch that issues handles resolvable only from its finished
    /// output.
    #[must_use]
    pub fn batch(&self) -> RedactionBatch {
        RedactionBatch::from_session(self.batch_runtime())
    }

    /// Redacts one scalar field through a complete one-item transaction.
    #[must_use]
    pub fn redact_field<T>(&self, field: &str, value: &T) -> RedactionTextOutput
    where
        T: std::fmt::Display + ?Sized,
    {
        let mut batch = self.batch();
        let handle = batch.redact_field(field, value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one scalar field without rendering its value.
    pub fn inspect_field(&self, field: &str, value: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        session.inspect_field(field, value);
        session.finish()
    }

    /// Redacts an argument vector through one completed batch operation.
    #[must_use]
    pub fn redact_argv<'items, I>(&self, items: I) -> RedactionTextOutput
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut batch = self.batch();
        let handle = batch.redact_argv(items);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects explicitly classified argv items without rendering them.
    pub fn inspect_argv<'items, I>(&self, items: I) -> RedactionInspectionResult
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut session = self.inspection_runtime();
        crate::formats::argv::inspection::inspect_items(&mut session, items, false);
        session.finish()
    }

    /// Redacts argv items using heuristic option classification.
    #[must_use]
    pub fn redact_heuristic_argv<'items, I>(&self, items: I) -> RedactionTextOutput
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut batch = self.batch();
        let handle = batch.redact_heuristic_argv(items);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects argv items using heuristic option classification.
    pub fn inspect_heuristic_argv<'items, I>(&self, items: I) -> RedactionInspectionResult
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        let mut session = self.inspection_runtime();
        crate::formats::argv::inspection::inspect_items(&mut session, items, true);
        session.finish()
    }

    /// Redacts one environment assignment through one completed transaction.
    #[must_use]
    pub fn redact_env(&self, name: &str, value: &str) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_env(name, value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one environment assignment without rendering it.
    pub fn inspect_env(&self, name: &str, value: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::env::inspection::inspect_pair(&mut session, name, value);
        session.finish()
    }

    /// Redacts environment assignments through one completed transaction.
    #[must_use]
    pub fn redact_env_pairs<'items, I>(&self, pairs: I) -> RedactionTextOutput
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        let mut batch = self.batch();
        let handle = batch.redact_env_pairs(pairs);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects environment assignments without rendering them.
    pub fn inspect_env_pairs<'items, I>(&self, pairs: I) -> RedactionInspectionResult
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        let mut session = self.inspection_runtime();
        crate::formats::env::inspection::inspect_os_pairs(&mut session, pairs);
        session.finish()
    }

    /// Redacts one process command through one completed batch transaction.
    #[must_use]
    pub fn redact_process<'arguments, 'variables, A, E>(
        &self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionTextOutput
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        let mut batch = self.batch();
        let handle = batch.redact_process(program, arguments, variables);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one process command without rendering its components.
    pub fn inspect_process<'arguments, 'variables, A, E>(
        &self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionInspectionResult
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        let mut session = self.inspection_runtime();
        let command = std::iter::once(crate::formats::argv::ArgvItem::plain(program)).chain(arguments);
        crate::formats::argv::inspection::inspect_items(&mut session, command, true);
        crate::formats::env::inspection::inspect_os_pairs(&mut session, variables);
        session.finish()
    }

    /// Redacts JSON text through one completed batch transaction.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn redact_json(&self, text: &str) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_json(text);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Redacts a borrowed parsed JSON value without taking ownership of it.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn redact_json_value(&self, value: &serde_json::Value) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_json_value(value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one JSON document without rendering it.
    #[cfg(feature = "json")]
    pub fn inspect_json(&self, text: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::json::inspection::inspect_text(&mut session, text);
        session.finish()
    }

    /// Inspects a borrowed parsed JSON value without taking ownership of it.
    #[cfg(feature = "json")]
    pub fn inspect_json_value(&self, value: &serde_json::Value) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::json::inspection::inspect_borrowed_value(&mut session, value);
        session.finish()
    }

    /// Redacts an HTTP URL through one completed batch transaction.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_url(&self, value: &str) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_http_url(value);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one HTTP URL without rendering it.
    #[cfg(feature = "http")]
    pub fn inspect_http_url(&self, value: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_url(&mut session, value);
        session.finish()
    }

    /// Redacts an HTTP header collection through one completed transaction.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_headers(&self, headers: &http::HeaderMap) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_http_headers(headers);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects HTTP headers without rendering their values.
    #[cfg(feature = "http")]
    pub fn inspect_http_headers(&self, headers: &http::HeaderMap) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_headers(&mut session, headers);
        session.finish()
    }

    /// Redacts one captured HTTP body through one completed session
    /// transaction.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_body(
        &self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_http_body(capture, content_type);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one captured HTTP body without rendering it.
    #[cfg(feature = "http")]
    pub fn inspect_http_body(
        &self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_body(&mut session, capture, content_type);
        session.finish()
    }

    /// Redacts one captured HTTP body using textual Content-Type metadata.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_body_with_content_type_text(
        &self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_http_body_with_content_type_text(capture, content_type);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one captured HTTP body using textual Content-Type metadata.
    #[cfg(feature = "http")]
    pub fn inspect_http_body_with_content_type_text(
        &self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_body_with_content_type_text(&mut session, capture, content_type);
        session.finish()
    }

    /// Redacts a URI through one completed batch transaction.
    #[cfg(feature = "uri")]
    #[must_use]
    pub fn redact_uri(&self, input: &str) -> RedactionTextOutput {
        let mut batch = self.batch();
        let handle = batch.redact_uri(input);
        batch
            .finish()
            .into_resolved(handle)
            .expect("a handle created by the completed transaction must resolve")
    }

    /// Inspects one URI without rendering it.
    #[cfg(feature = "uri")]
    pub fn inspect_uri(&self, input: &str) -> RedactionInspectionResult {
        let mut session = self.inspection_runtime();
        crate::formats::uri::inspection::inspect_uri(&mut session, input);
        session.finish()
    }
}

impl Default for Redactor {
    /// Creates a redactor from the deterministic standard policy.
    ///
    /// # Returns
    ///
    /// This implementation never reads mutable process-wide application state.
    #[inline(always)]
    fn default() -> Self {
        Self::standard()
    }
}

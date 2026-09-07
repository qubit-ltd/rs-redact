// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Consumption-based construction of one ordered redacted text.

use std::fmt::Display;

use crate::RedactionTextOutput;
use crate::domain::Redact;
use crate::runtime::TextSession;

/// Builds one ordered, redacted text value through consuming chained calls.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::strict()
///     .text_composer()
///     .literal("password=")
///     .field("password", "raw-secret")
///     .finish();
/// assert!(!output.text().as_str().contains("raw-secret"));
/// ```
pub struct RedactedTextComposer {
    /// Typed transaction that exclusively owns this composer's text output.
    session: TextSession,
}

impl RedactedTextComposer {
    /// Creates a composer backed by one private runtime transaction.
    ///
    /// # Parameters
    ///
    /// - `session`: Fresh text transaction exclusively owned by this composer.
    ///
    /// # Returns
    ///
    /// A composer retaining the transaction and its shared budget.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn from_session(session: TextSession) -> Self {
        Self { session }
    }

    /// Appends trusted program-authored text.
    ///
    /// # Parameters
    ///
    /// - `text`: Trusted static program text, escaped and counted against
    ///   output capacity.
    ///
    /// # Returns
    ///
    /// This composer after attempting to append the literal.
    #[must_use]
    #[inline(always)]
    pub fn literal(mut self, text: &'static str) -> Self {
        let _ = self.session.literal(text);
        self
    }

    /// Redacts and appends one scalar field.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Lazily evaluated scalar formatter.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw scalar key used for admission and policy classification.
    /// - `value`: Scalar formatted only when admission and masking require it.
    ///
    /// # Returns
    ///
    /// This composer after recording the scalar result and accounting.
    #[must_use]
    #[inline(always)]
    pub fn field<T>(mut self, field: &str, value: &T) -> Self
    where
        T: Display + ?Sized,
    {
        let _ = self.session.field(field, value);
        self
    }

    /// Redacts and appends one domain value.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Domain type exposing structured redaction.
    ///
    /// # Parameters
    ///
    /// - `value`: Domain value visited through its structured redaction
    ///   contract.
    ///
    /// # Returns
    ///
    /// This composer after recording the domain result and accounting.
    #[must_use]
    #[inline(always)]
    pub fn value<T>(mut self, value: &T) -> Self
    where
        T: Redact + ?Sized,
    {
        let _ = self.session.value(value);
        self
    }

    /// Appends command-line text configured through the argv writer.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback whose writer borrow cannot escape the call.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback using the format writer and this
    ///   transaction’s remaining budget.
    ///
    /// # Returns
    ///
    /// This composer retaining the updated output and execution summary.
    #[must_use]
    #[inline(always)]
    pub fn argv<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::argv::ArgvRedactionWriter<'session>),
    {
        self.session.argv(configure);
        self
    }

    /// Appends environment text configured through the environment writer.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback whose writer borrow cannot escape the call.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback using the format writer and this
    ///   transaction’s remaining budget.
    ///
    /// # Returns
    ///
    /// This composer retaining the updated output and execution summary.
    #[must_use]
    #[inline(always)]
    pub fn env<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::env::EnvRedactionWriter<'session>),
    {
        self.session.env(configure);
        self
    }

    /// Appends process text configured through the process writer.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback whose writer borrow cannot escape the call.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback using the format writer and this
    ///   transaction’s remaining budget.
    ///
    /// # Returns
    ///
    /// This composer retaining the updated output and execution summary.
    #[must_use]
    #[inline(always)]
    pub fn process<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::process::ProcessRedactionWriter<'session>),
    {
        let _ = self.session.process(configure);
        self
    }

    /// Appends JSON text configured through the JSON writer.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback whose writer borrow cannot escape the call.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback using the format writer and this
    ///   transaction’s remaining budget.
    ///
    /// # Returns
    ///
    /// This composer retaining the updated output and execution summary.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub fn json<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::json::JsonRedactionWriter<'session>),
    {
        let _ = self.session.json(configure);
        self
    }

    /// Appends HTTP text configured through the HTTP writer.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback whose writer borrow cannot escape the call.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback using the format writer and this
    ///   transaction’s remaining budget.
    ///
    /// # Returns
    ///
    /// This composer retaining the updated output and execution summary.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub fn http<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::http::HttpRedactionWriter<'session>),
    {
        let _ = self.session.http(configure);
        self
    }

    /// Appends URI text configured through the URI writer.
    ///
    /// # Type Parameters
    ///
    /// - `F`: Callback whose writer borrow cannot escape the call.
    ///
    /// # Parameters
    ///
    /// - `configure`: One-shot callback using the format writer and this
    ///   transaction’s remaining budget.
    ///
    /// # Returns
    ///
    /// This composer retaining the updated output and execution summary.
    #[cfg(feature = "uri")]
    #[must_use]
    #[inline(always)]
    pub fn uri<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::uri::UriRedactionWriter<'session>),
    {
        let _ = self.session.uri(configure);
        self
    }

    /// Consumes the composer and publishes its redacted text and summary.
    ///
    /// # Returns
    ///
    /// The completed text and its actual completion, reasons, and resource
    /// accounting.
    #[must_use]
    #[inline(always)]
    pub fn finish(self) -> RedactionTextOutput {
        self.session.finish()
    }
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Consumption-based construction of one ordered redacted text.

use crate::RedactionTextOutput;
use crate::domain::Redact;
use crate::runtime::RedactionSession;

/// Builds one ordered, redacted text value through consuming chained calls.
pub struct RedactedTextComposer {
    session: RedactionSession,
}

impl RedactedTextComposer {
    /// Creates a composer backed by one private runtime transaction.
    #[must_use]
    pub(crate) const fn from_session(session: RedactionSession) -> Self {
        Self { session }
    }

    /// Appends trusted program-authored text.
    #[must_use]
    pub fn literal(mut self, text: &'static str) -> Self {
        let _ = self.session.literal(text);
        self
    }

    /// Redacts and appends one scalar field.
    #[must_use]
    pub fn field(mut self, field: &str, value: &str) -> Self {
        let _ = self.session.field(field, value);
        self
    }

    /// Redacts and appends one domain value.
    #[must_use]
    pub fn value<T>(mut self, value: &T) -> Self
    where
        T: Redact + ?Sized,
    {
        let _ = self.session.value(value);
        self
    }

    /// Appends command-line text configured through the argv writer.
    #[must_use]
    pub fn argv<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::argv::ArgvRedactionWriter<'session>),
    {
        self.session.argv(configure);
        self
    }

    /// Appends environment text configured through the environment writer.
    #[must_use]
    pub fn env<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::env::EnvRedactionWriter<'session>),
    {
        self.session.env(configure);
        self
    }

    /// Appends process text configured through the process writer.
    #[must_use]
    pub fn process<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::process::ProcessRedactionWriter<'session>),
    {
        let _ = self.session.process(configure);
        self
    }

    /// Appends JSON text configured through the JSON writer.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn json<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::json::JsonRedactionWriter<'session>),
    {
        let _ = self.session.json(configure);
        self
    }

    /// Appends HTTP text configured through the HTTP writer.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn http<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::http::HttpRedactionWriter<'session>),
    {
        let _ = self.session.http(configure);
        self
    }

    /// Appends URI text configured through the URI writer.
    #[cfg(feature = "uri")]
    #[must_use]
    pub fn uri<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut crate::formats::uri::UriRedactionWriter<'session>),
    {
        let _ = self.session.uri(configure);
        self
    }

    /// Consumes the composer and publishes its redacted text and summary.
    #[must_use]
    pub fn finish(mut self) -> RedactionTextOutput {
        self.session.finish_text()
    }
}

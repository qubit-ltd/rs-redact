// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed diagnostic views carrying an immutable policy snapshot.

use std::fmt;

use crate::Redact;
use crate::Redactor;

/// A lazy view of a source value under one fixed redaction policy.
///
/// Creation does not inspect or format the source. Each formatting or Serde
/// call starts a fresh execution and budget, reading the source again. The
/// policy is fixed, but interior-mutable source values are not snapshotted.
/// This is neither a modified business object nor cached redacted output.
/// Use [`Redactor::redact_text`] when a finalized text and summary are needed.
///
/// With `serde` or `json`, values implementing `RedactSerialize` can be
/// serialized structurally through this view. The source's ordinary
/// `Serialize` implementation is not used as the root redaction entry point.
pub struct RedactedView<'value, T: ?Sized> {
    /// Source borrowed until the view is dropped.
    value: &'value T,
    /// Owned policy snapshot independent of the application default.
    redactor: Redactor,
}

impl<'value, T: ?Sized> RedactedView<'value, T> {
    /// Captures `redactor` without reading or formatting `value`.
    pub(crate) fn new(value: &'value T, redactor: Redactor) -> Self {
        Self { value, redactor }
    }
}

impl<T: Redact + ?Sized> fmt::Display for RedactedView<'_, T> {
    /// Renders the source once through a fresh text transaction.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.redactor.redact_text(self.value).text().as_str())
    }
}

impl<T: Redact + ?Sized> fmt::Debug for RedactedView<'_, T> {
    /// Shows redacted text without exposing wrapper internals or source Debug.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[cfg(any(feature = "serde", feature = "json"))]
impl<T: crate::RedactSerialize + ?Sized> serde::Serialize for RedactedView<'_, T> {
    /// Serializes with this view's policy, propagating serializer/budget
    /// errors.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use crate::domain::internal::RedactedSerializeRef;
        RedactedSerializeRef::new(self.value, self.redactor.policy()).serialize(serializer)
    }
}

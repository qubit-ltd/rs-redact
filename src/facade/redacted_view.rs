// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed diagnostic views carrying an immutable policy snapshot.

use std::fmt;

#[cfg(feature = "serde")]
use serde::Serialize;
#[cfg(feature = "serde")]
use serde::Serializer;

use crate::Redact;
use crate::Redactor;
#[cfg(feature = "serde")]
use crate::domain::internal::RedactSerializeSource;
#[cfg(feature = "serde")]
use crate::domain::internal::RedactedProjectionRef;

/// A lazy view of a source value under one fixed redaction policy.
///
/// Creation does not inspect or format the source. Each formatting or Serde
/// call starts a fresh execution and budget, reading the source again. The
/// policy is fixed, but interior-mutable source values are not snapshotted.
/// This is neither a modified business object nor cached redacted output.
/// Use [`Redactor::redact_text`] when a finalized text and summary are needed.
///
/// With the `serde` feature, views of derived values serialize structurally
/// through their redacted field projections. The source's ordinary `Serialize`
/// implementation is not used as the root redaction entry point.
/// Direct Serde observes logical payload limits; an external serializer owns
/// its final encoded size. `Redactor::to_json` also bounds final JSON bytes.
///
/// # Type Parameters
///
/// - `'value`: Lifetime of the borrowed source.
/// - `T`: Source type; formatting/serialization capabilities are required on
///   use.
///
/// # Examples
///
/// ```
/// use qubit_redact::{Redact, RedactionWriter, Redactor};
/// struct Event;
/// impl Redact for Event {
///     fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
///         writer.record("Event", |fields| {
///             fields.unmarked("status", || "ready");
///         });
///     }
/// }
/// let event = Event;
/// let redactor = Redactor::standard();
/// let view = redactor.redact_view(&event);
/// assert_eq!(format!("{view}"), redactor.redact_text(&event).text().as_str());
/// ```
pub struct RedactedView<'value, T: ?Sized> {
    /// Source borrowed until the view is dropped.
    value: &'value T,
    /// Owned policy snapshot independent of the application default.
    redactor: Redactor,
}

impl<'value, T: ?Sized> RedactedView<'value, T> {
    /// Captures `redactor` without reading or formatting `value`.
    ///
    /// # Parameters
    ///
    /// - `value`: Source retained by reference without evaluation.
    /// - `redactor`: Owned immutable policy snapshot used for every later
    ///   execution.
    ///
    /// # Returns
    ///
    /// A lazy view retaining both source borrow and policy snapshot.
    #[must_use]
    #[inline(always)]
    pub(crate) fn new(value: &'value T, redactor: Redactor) -> Self {
        Self { value, redactor }
    }
}

impl<T: Redact + ?Sized> fmt::Display for RedactedView<'_, T> {
    /// Renders the source once through a fresh text transaction.
    ///
    /// # Parameters
    ///
    /// - `formatter`: Destination receiving the redacted text of a fresh
    ///   execution.
    ///
    /// # Returns
    ///
    /// Success after publishing the rendered text.
    ///
    /// # Errors
    ///
    /// Propagates a destination formatting error; redaction failures remain
    /// safe output metadata.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.redactor.redact_text(self.value).text().as_str())
    }
}

impl<T: Redact + ?Sized> fmt::Debug for RedactedView<'_, T> {
    /// Shows redacted text without exposing wrapper internals or source Debug.
    ///
    /// # Parameters
    ///
    /// - `formatter`: Destination receiving the redacted text of a fresh
    ///   execution.
    ///
    /// # Returns
    ///
    /// Success after publishing the rendered text.
    ///
    /// # Errors
    ///
    /// Propagates a destination formatting error; redaction failures remain
    /// safe output metadata.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[cfg(feature = "serde")]
impl<'value, T: RedactSerializeSource + ?Sized> Serialize for RedactedView<'value, T>
where
    T::RedactedFields<'value>: Serialize,
{
    /// Serializes with this view's policy, propagating serializer/budget
    /// errors.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer and its result/error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the structured redacted
    ///   projection.
    ///
    /// # Returns
    ///
    /// The destination result after one policy-scoped structured execution.
    ///
    /// # Errors
    ///
    /// Returns the serializer’s error for rejected admission or payload
    /// budgets, or propagates a downstream serialization error.
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RedactedProjectionRef::new(self.value, self.redactor.policy()).serialize(serializer)
    }
}

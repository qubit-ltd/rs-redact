// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy redaction view selected by an external field key.

use std::{
    fmt::Write as _,
    fmt::{
        self,
        Debug,
        Display,
        Formatter,
    },
};

use crate::{
    LogOutputLimit,
    Redact,
    RedactValue,
    RedactionPolicy,
    RedactionSession,
    policy::ResolvedField,
    text::internal::LogEscapeWriter,
};

use super::{
    bounded_redacted_display::format_debug_bounded,
    internal::mask_byte_limit,
};

/// A borrowed value rendered according to a separate field key.
///
/// The key is used only to select a policy rule. The view itself renders or
/// serializes the value, and borrows an immutable policy snapshot.
///
/// # Type Parameters
///
/// * `'value` - Lifetime of the borrowed key and value.
/// * `'policy` - Lifetime of the borrowed policy snapshot.
/// * `T` - Value type rendered or serialized through redaction.
#[must_use = "format or serialize the keyed redaction view"]
pub struct RedactedKeyedValue<'value, 'policy, T: ?Sized> {
    /// Field name used for policy classification.
    key: &'value str,
    /// Value represented by this view.
    value: &'value T,
    /// Immutable policy snapshot borrowed by every output protocol.
    policy: &'policy RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedKeyedValue<'value, 'policy, T> {
    /// Creates a keyed view from borrowed inputs and a borrowed policy
    /// snapshot.
    ///
    /// # Parameters
    ///
    /// * `key` - Field name used only for policy classification.
    /// * `value` - Value to render or serialize lazily.
    /// * `policy` - Complete policy snapshot borrowed by this view.
    ///
    /// # Returns
    ///
    /// A view that never modifies the original value.
    #[must_use = "format or serialize the keyed redaction view"]
    #[inline(always)]
    pub const fn new(
        key: &'value str,
        value: &'value T,
        policy: &'policy RedactionPolicy,
    ) -> Self {
        Self { key, value, policy }
    }

    /// Returns the external field key used by this view.
    ///
    /// # Returns
    ///
    /// The unchanged policy lookup key.
    #[must_use]
    #[inline(always)]
    pub const fn key(&self) -> &'value str {
        self.key
    }
}

impl<T: Redact + RedactValue + ?Sized> Debug for RedactedKeyedValue<'_, '_, T> {
    /// Formats the value through its selected field classification.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatter whose flags are preserved.
    ///
    /// # Returns
    ///
    /// The complete redacted debug result.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let session = RedactionSession::diagnostic(self.policy);
        let view =
            RedactedKeyedValueSession::new(self.key, self.value, &session);
        if mask_byte_limit().is_some() {
            return Debug::fmt(&view, formatter);
        }
        format_debug_bounded(
            &view,
            LogOutputLimit::from(self.policy.limits().diagnostic_event()),
            formatter,
        )
    }
}

/// A keyed value view that reuses one diagnostic session.
#[must_use = "format the keyed redacted value view"]
pub struct RedactedKeyedValueSession<'value, 'session, 'policy, T: ?Sized> {
    key: &'value str,
    value: &'value T,
    session: &'session RedactionSession<'policy>,
}

impl<'value, 'session, 'policy, T: ?Sized>
    RedactedKeyedValueSession<'value, 'session, 'policy, T>
{
    /// Creates a keyed view borrowing an existing diagnostic session.
    #[inline(always)]
    pub fn new(
        key: &'value str,
        value: &'value T,
        session: &'session RedactionSession<'policy>,
    ) -> Self {
        Self {
            key,
            value,
            session,
        }
    }
}

impl<T: Redact + RedactValue + ?Sized> Debug
    for RedactedKeyedValueSession<'_, '_, '_, T>
{
    /// Formats the value through its selected classification and shared
    /// session.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let policy = self.session.policy();
        let resolved = policy.resolve_field(self.key);
        match resolved {
            ResolvedField::Sensitive { sensitivity } => Debug::fmt(
                &self.value.redact_value(sensitivity, policy.masking()),
                formatter,
            ),
            ResolvedField::PassThrough => {
                self.value.fmt_redacted(self.session, formatter)
            }
        }
    }
}

impl<T: Redact + RedactValue + ?Sized> Display
    for RedactedKeyedValueSession<'_, '_, '_, T>
{
    /// Escapes the selected redacted representation for plain-text logs.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = LogEscapeWriter::new(formatter);
        write!(&mut writer, "{self:?}")
    }
}

impl<T: Redact + RedactValue + ?Sized> Display
    for RedactedKeyedValue<'_, '_, T>
{
    /// Formats the selected redacted representation for a plain-text log.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination plain-text log boundary.
    ///
    /// # Returns
    ///
    /// The complete escaped redacted representation.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete escaped representation.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let session = RedactionSession::diagnostic(self.policy);
        let view =
            RedactedKeyedValueSession::new(self.key, self.value, &session);
        let mut writer = LogEscapeWriter::new(formatter);
        write!(&mut writer, "{view:?}")
    }
}

#[cfg(feature = "serde")]
impl<T: RedactValue + crate::domain::RedactSerialize + ?Sized> serde::Serialize
    for RedactedKeyedValue<'_, '_, T>
{
    /// Serializes the value through its selected field classification.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Destination Serde serializer type.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Destination serde serializer.
    ///
    /// # Returns
    ///
    /// The serializer's successful redacted output.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer's error unchanged.
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let resolved = self.policy.resolve_field(self.key);
        match resolved {
            ResolvedField::Sensitive { sensitivity } => {
                serde::Serialize::serialize(
                    &self
                        .value
                        .redact_value(sensitivity, self.policy.masking()),
                    serializer,
                )
            }
            ResolvedField::PassThrough => {
                crate::domain::RedactSerialize::serialize_redacted(
                    self.value,
                    self.policy,
                    serializer,
                )
            }
        }
    }
}

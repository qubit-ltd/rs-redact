// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed redaction projections for optional nested values.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;

use super::redact_serialize::RedactSerialize;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_serialize_ref::RedactedSerializeRef;
use crate::RedactionPolicy;

/// Borrows an optional container for structured redacted field traversal.
///
/// # Type Parameters
///
/// * `'a`: The source borrow lifetime.
/// * `T`: The nested source type.
pub struct OptionProjection<'a, T>(
    /// The optional source borrowed for this traversal.
    &'a Option<T>,
);

impl<T> RedactSerializeSource for Option<T> {
    /// A projection borrowing the source container.
    type RedactedFields<'a>
        = OptionProjection<'a, T>
    where
        Self: 'a;

    /// Borrows the source; the caller must establish a serialization scope.
    #[inline(always)]
    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        OptionProjection(self)
    }
}

impl<'value, T> Serialize for OptionProjection<'value, T>
where
    T: RedactSerialize,
{
    /// Serializes the container within the current redaction scope.
    ///
    /// # Type Parameters
    ///
    /// * `S`: The destination serializer.
    ///
    /// # Parameters
    ///
    /// * `serializer`: The destination for the redacted representation.
    ///
    /// # Returns
    ///
    /// The serializer's output after applying the active policy and budgets.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when no redaction scope is active, or
    /// propagates errors from the destination serializer.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policy_owner =
            current_policy().ok_or_else(|| S::Error::custom("serialization requires an active redaction scope"))?;
        let Self(value) = self;
        match *value {
            Some(value) => RedactedSerializeRef::new(value, policy_owner.as_ref()).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed redaction projections for optional nested values.

use serde::Serialize;
use serde::Serializer;

use super::redact_serialize::RedactSerialize;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_serialize_ref::RedactedSerializeRef;
use crate::RedactionPolicy;

/// Borrows an optional container for structured redacted field traversal.
pub struct OptionProjection<'a, T>(&'a Option<T>);

impl<T> RedactSerializeSource for Option<T> {
    type RedactedFields<'a>
        = OptionProjection<'a, T>
    where
        Self: 'a;

    #[inline(always)]
    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        OptionProjection(self)
    }
}

impl<'value, T> Serialize for OptionProjection<'value, T>
where
    T: RedactSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            Some(value) => {
                let policy_owner = current_policy().expect("active scope");
                RedactedSerializeRef::new(value, policy_owner.as_ref()).serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }
}

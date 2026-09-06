// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed projections generated for redacted structured serialization.

use crate::RedactionPolicy;

/// Borrows the field projection used for redacted structured serialization.
///
/// The associated projection deliberately has no `Serialize` bound. This lets
/// a `Redact` implementation exist for text-only values; Serde reports a
/// trait-bound error only when callers request structured serialization.
pub trait RedactSerializeSource {
    /// A borrowed projection of this value's fields.
    type RedactedFields<'a>
    where
        Self: 'a;

    /// Borrows the fields under `policy` without cloning the source value.
    fn redacted_fields<'value>(&'value self, policy: &RedactionPolicy) -> Self::RedactedFields<'value>;
}

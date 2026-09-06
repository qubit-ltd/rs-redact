// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generated structured serialization capability.

use serde::Serializer;

use crate::RedactionPolicy;

/// Structured redaction capability used by `Redactor::redact_view`.
///
/// Generate it with `#[redact(serde)]` when the type should provide structured
/// redaction and make its ordinary `Serialize` implementation redacted.
/// Custom implementations must propagate serializer errors and preserve the
/// supplied policy throughout nested redaction.
pub trait RedactSerialize {
    /// Serializes this value through its generated redaction policy adapter.
    fn serialize_redacted<S>(&self, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

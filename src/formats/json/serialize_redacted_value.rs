// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured publication of parsed JSON under the domain serialization budget.

use serde::Serialize;
use serde::Serializer;
use serde_json::Value;

use super::internal::RedactedValue;
use crate::RedactionPolicy;
use crate::domain::internal::BudgetSerialize;

/// Serializes borrowed parsed JSON without cloning, reparsing or text
/// conversion.
///
/// The budget serializer admits every emitted node and scalar before forwarding
/// it. Sensitive subtrees become opaque values through the same JSON policy as
/// text rendering.
///
/// # Errors
///
/// Returns serializer or shared resource-budget errors.
pub(crate) fn serialize_redacted_value<S: Serializer>(
    value: &Value,
    serializer: S,
    policy: &RedactionPolicy,
) -> Result<S::Ok, S::Error> {
    BudgetSerialize::new(RedactedValue::root(value, policy)).serialize(serializer)
}

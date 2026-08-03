// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explanations attached to URI redaction results.

use super::UriComponent;

/// Explains why a URI result was changed or rejected.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UriRedactionReason {
    /// A component was classified by the core field policy or URI policy.
    SensitiveComponent(UriComponent),
    /// A query key did not decode to valid UTF-8.
    UndecodableQueryKey,
    /// A query value did not decode to valid UTF-8.
    UndecodableQueryValue,
    /// The URI parser rejected the raw input.
    InvalidUri,
    /// The raw input exceeded the policy input budget.
    InputLimitExceeded,
    /// The safe result exceeded the policy output budget.
    OutputTruncated,
}

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

/// Legacy structured-redaction hook for manually implemented container
/// adapters. Derived domain values use the projection capability instead.
/// Implementations must serialize under the `policy` passed to the hook;
/// callers may invoke it directly without an existing serialization scope.
pub trait RedactSerialize {
    /// Serializes this value through a caller-supplied policy and scope.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream serialization failures.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the policy-selected
    ///   representation.
    /// - `policy`: Immutable policy supplied by the caller. This hook
    ///   establishes or joins the corresponding serialization scope.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    fn serialize_redacted<S>(&self, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

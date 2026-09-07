// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serialization capability attached to an actual source borrow.

use serde::Serializer;

use crate::RedactionPolicy;

/// Serializes an admitted borrowed source without a higher-ranked GAT bound.
///
/// Derive implements this trait on references, with capability predicates on
/// the concrete projection at that reference's lifetime. Generic source
/// serialization can then quantify over references without requiring borrowed
/// child data to be static. Text-only types retain conditional capability.
/// Implementations must open or join a [`super::RedactSerializeScope`] before
/// visiting the projection; adapters delegate without opening a second scope.
pub trait RedactBorrowedSerialize {
    /// Serializes this source borrow under an explicit policy.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted projection.
    /// - `policy`: Snapshot shared by the enclosing serialization scope.
    ///
    /// # Returns
    ///
    /// The destination result after serializing the borrowed projection.
    ///
    /// # Errors
    ///
    /// Propagates admission and downstream serialization failures.
    fn serialize_borrowed<S>(self, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

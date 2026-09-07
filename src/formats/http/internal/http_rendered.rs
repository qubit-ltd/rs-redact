// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP adapter publication wrapper for one runtime operation.

use crate::runtime::RenderedOperation;

/// One completed HTTP rendering owned by the parent transaction.
///
/// This is deliberately an implementation detail rather than an HTTP result
/// type: HTTP never publishes a second output model. The parent transaction
/// commits its text and completion into its composer or batch publication.
pub(in crate::formats::http) struct HttpRendered {
    /// Bounded text and provenance awaiting parent-session publication.
    operation: RenderedOperation,
}

impl HttpRendered {
    /// Wraps a completed operation for HTTP adapter publication.
    ///
    /// # Parameters
    ///
    /// - `operation`: Bounded fragment with completion and provenance.
    ///
    /// # Returns
    ///
    /// A wrapper retaining the operation without modifying its accounting.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn new(operation: RenderedOperation) -> Self {
        Self { operation }
    }

    /// Consumes this internal wrapper into the runtime operation
    /// representation.
    ///
    /// # Returns
    ///
    /// The original bounded operation ready for the parent transaction.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn into_operation(self) -> RenderedOperation {
        self.operation
    }
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
// qubit-style: allow source-test-pair
//! HTTP field-policy contexts.

use crate::PolicyLocation;

/// Selects one HTTP field namespace for policy configuration.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HttpFieldContext {
    /// HTTP header names.
    Header,
    /// Query-string and form names.
    Query,
    /// Structured body field names.
    Body,
}

impl HttpFieldContext {
    /// Returns the validation location corresponding to this context.
    pub(crate) const fn location(self) -> PolicyLocation {
        match self {
            Self::Header => PolicyLocation::HttpHeader,
            Self::Query => PolicyLocation::HttpQuery,
            Self::Body => PolicyLocation::HttpBody,
        }
    }
}

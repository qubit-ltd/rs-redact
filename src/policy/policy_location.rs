// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Location of a policy-building validation error.

use std::fmt;

/// Policy construction context where a validation error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyLocation {
    /// Regular field-rule construction context.
    Rules,
    /// Floor construction context.
    Floor,
    /// HTTP header field rules in an HTTP policy builder.
    HttpHeader,
    /// HTTP query and form field rules in an HTTP policy builder.
    HttpQuery,
    /// HTTP body field rules in an HTTP policy builder.
    HttpBody,
    /// Shared HTTP masking policy.
    HttpMasking,
}

impl fmt::Display for PolicyLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rules => formatter.write_str("rules"),
            Self::Floor => formatter.write_str("floor"),
            Self::HttpHeader => formatter.write_str("http header"),
            Self::HttpQuery => formatter.write_str("http query"),
            Self::HttpBody => formatter.write_str("http body"),
            Self::HttpMasking => formatter.write_str("http masking"),
        }
    }
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Validation errors for domain-structure redaction limits.

use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

/// Reports which domain-structure limit was configured as zero.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainRedactionLimitsError {
    /// The cumulative domain-node limit was zero.
    ZeroMaxNodes,
    /// The cumulative collection-item limit was zero.
    ZeroMaxCollectionItems,
    /// The active domain-value depth limit was zero.
    ZeroMaxDepth,
}

impl Display for DomainRedactionLimitsError {
    /// Writes a concise description of the violated limit invariant.
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxNodes => formatter
                .write_str("domain node limit must be greater than zero"),
            Self::ZeroMaxCollectionItems => formatter.write_str(
                "domain collection item limit must be greater than zero",
            ),
            Self::ZeroMaxDepth => formatter
                .write_str("domain depth limit must be greater than zero"),
        }
    }
}

impl Error for DomainRedactionLimitsError {}

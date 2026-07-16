// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
/// Field-name matching mode used for sensitivity lookup.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameMatchMode {
    /// Match only the canonicalized field name exactly.
    Exact,
    /// Match exactly first, then match suffixes at separator or camel-case
    /// token boundaries.
    ExactOrSuffix,
}

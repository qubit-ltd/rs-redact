// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URI components that can carry sensitive data.

/// A URI component whose redaction was controlled by the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UriComponent {
    /// The userinfo username before the first raw colon.
    Username,
    /// The userinfo password after the first raw colon.
    Password,
    /// One or more query values classified by the core field policy.
    Query,
    /// The URI path when path redaction is enabled.
    Path,
    /// The URI fragment when fragment redaction is enabled.
    Fragment,
}

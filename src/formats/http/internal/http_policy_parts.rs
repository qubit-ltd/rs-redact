// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared private components of an immutable HTTP redaction policy.

use super::super::TextBodyPolicy;
use super::super::UrlPathPolicy;
use crate::RedactionRules;

/// Validated HTTP components moved directly into the policy’s shared snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::formats::http) struct HttpPolicyParts {
    /// Validated header classification snapshot.
    pub(in crate::formats::http) header_rules: RedactionRules,
    /// Validated query and form classification snapshot.
    pub(in crate::formats::http) query_rules: RedactionRules,
    /// Validated structured-body classification snapshot.
    pub(in crate::formats::http) body_rules: RedactionRules,
    /// Validated URL path visibility choice.
    pub(in crate::formats::http) url_path_policy: UrlPathPolicy,
    /// Validated opaque text-body visibility choice.
    pub(in crate::formats::http) text_body_policy: TextBodyPolicy,
}

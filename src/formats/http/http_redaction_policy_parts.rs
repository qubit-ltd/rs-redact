// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Complete private construction state for an HTTP redaction policy.
// qubit-style: allow type-file-name

use super::TextBodyPolicy;
use super::UrlPathPolicy;
use crate::RedactionRules;

/// Complete private construction state for an HTTP redaction policy.
pub(super) struct HttpPolicyParts {
    /// Validated header classification snapshot.
    pub(super) header_rules: RedactionRules,
    /// Validated query and form classification snapshot.
    pub(super) query_rules: RedactionRules,
    /// Validated structured-body classification snapshot.
    pub(super) body_rules: RedactionRules,
    /// Validated URL path visibility choice.
    pub(super) url_path_policy: UrlPathPolicy,
    /// Validated opaque text-body visibility choice.
    pub(super) text_body_policy: TextBodyPolicy,
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Complete private construction state for an HTTP redaction policy.

use crate::{
    DiagnosticBudget,
    JsonDepthBudget,
    RedactionRules,
};

use super::{
    BodyBudget,
    TextBodyPolicy,
    UnkeyedJsonValuePolicy,
    UrlPathPolicy,
};

/// Complete private construction state for an HTTP redaction policy.
pub(super) struct HttpRedactionPolicyParts {
    pub(super) header_rules: RedactionRules,
    pub(super) query_rules: RedactionRules,
    pub(super) body_rules: RedactionRules,
    pub(super) diagnostic_budget: DiagnosticBudget,
    pub(super) body_budget: BodyBudget,
    pub(super) json_depth_budget: JsonDepthBudget,
    pub(super) url_path_policy: UrlPathPolicy,
    pub(super) text_body_policy: TextBodyPolicy,
    pub(super) unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
}

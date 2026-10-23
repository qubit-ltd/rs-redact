// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-key classification contracts for the shared domain policy helper.

use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::domain::internal::resolve_keyed_field;
use crate::policy::ResolvedField;

#[test]
fn test_keyed_lookup_uses_policy_classification_for_runtime_keys() {
    let policy = RedactionPolicy::standard();
    assert!(matches!(
        resolve_keyed_field(&policy, "password"),
        ResolvedField::Sensitive {
            sensitivity: Sensitivity::Secret
        }
    ));
    assert!(matches!(
        resolve_keyed_field(&policy, "display_name"),
        ResolvedField::PassThrough
    ));
}

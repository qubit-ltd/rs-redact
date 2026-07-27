// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`SensitiveFieldRule`](qubit_redact::SensitiveFieldRule) views.

use qubit_redact::{
    RedactionPolicy,
    SensitiveFieldRule,
    Sensitivity,
};

/// Alternate field query used as an unselected function-pointer target.
const fn alternate_field(_rule: &SensitiveFieldRule<'static>) -> &'static str {
    "alternate"
}

/// Alternate sensitivity query used as an unselected function target.
const fn alternate_sensitivity(
    _rule: &SensitiveFieldRule<'static>,
) -> Sensitivity {
    Sensitivity::Low
}

/// Verifies a configured sensitive rule exposes its field and level.
#[test]
fn test_sensitive_field_rule_exposes_configuration() {
    let policy: &'static RedactionPolicy = Box::leak(Box::new(
        RedactionPolicy::empty_builder()
            .raise("tenant_secret", Sensitivity::High)
            .build()
            .expect("the configured rule should be valid"),
    ));
    let rule = std::hint::black_box(
        policy
            .sensitive_rules()
            .next()
            .expect("the configured sensitive rule should be visible"),
    );
    let selected = usize::from(std::process::id() == 0);
    let fields: [for<'a> fn(&'a SensitiveFieldRule<'static>) -> &'static str;
        2] = [SensitiveFieldRule::field, alternate_field];
    let sensitivities: [for<'a> fn(
        &'a SensitiveFieldRule<'static>,
    ) -> Sensitivity; 2] =
        [SensitiveFieldRule::sensitivity, alternate_sensitivity];

    assert_eq!(fields[selected](&rule), "tenantsecret");
    assert_eq!(sensitivities[selected](&rule), Sensitivity::High);
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactionPolicyBuilder`](qubit_redact::RedactionPolicyBuilder).

use qubit_redact::InputOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::PolicyError;
use qubit_redact::PolicyLocation;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
#[cfg(feature = "json")]
use qubit_redact::UnkeyedJsonValuePolicy;
#[cfg(feature = "http")]
use qubit_redact::http::TextBodyPolicy;
#[cfg(feature = "http")]
use qubit_redact::http::UrlPathPolicy;
use qubit_redact::policy::DomainRedactionLimits;
#[cfg(feature = "uri")]
use qubit_redact::uri::UriFragmentPolicy;
#[cfg(feature = "uri")]
use qubit_redact::uri::UriPathPolicy;

/// Verifies grouped field and limit setters chain without consuming the root
/// builder.
#[test]
fn test_redaction_policy_builder_chains_grouped_fields_and_limits() {
    let diagnostic = InputOutputLimit::new(128, 256)
        .expect("the diagnostic limit should be valid");
    let operation = InputOutputLimit::new(512, 1024)
        .expect("the operation limit should be valid");
    let domain = DomainRedactionLimits::new(8, 4, 2)
        .expect("the domain limits should be valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .raise("token", Sensitivity::Secret)
        .expect("the first field should be valid")
        .raise("password", Sensitivity::Secret)
        .expect("the second field should be valid");
    builder
        .limits()
        .diagnostic_event(diagnostic)
        .ordinary_operation(operation)
        .domain(domain);
    let policy = builder.build().expect("the policy should be valid");

    assert_eq!(policy.sensitivity_for("token"), Some(Sensitivity::Secret));
    assert_eq!(
        policy.sensitivity_for("password"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(policy.limits().diagnostic_event(), diagnostic);
    assert_eq!(policy.limits().ordinary_operation(), operation);
    assert_eq!(policy.limits().domain(), domain);
}

/// Verifies consecutive HTTP setters preserve their last-call-wins behavior.
#[cfg(feature = "http")]
#[test]
fn test_redaction_policy_builder_chains_http_settings() {
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .url_path(UrlPathPolicy::Redact)
        .text_body(TextBodyPolicy::PassThrough)
        .url_path(UrlPathPolicy::Preserve);
    let policy = builder.build().expect("the HTTP policy should be valid");

    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Preserve);
    assert_eq!(
        policy.http().text_body_policy(),
        TextBodyPolicy::PassThrough,
    );
}

/// Verifies consecutive URI setters preserve their last-call-wins behavior.
#[cfg(feature = "uri")]
#[test]
fn test_redaction_policy_builder_chains_uri_settings() {
    let mut builder = RedactionPolicy::builder();
    builder
        .uri()
        .path(UriPathPolicy::Redact)
        .fragment(UriFragmentPolicy::Preserve)
        .path(UriPathPolicy::Preserve);
    let policy = builder.build().expect("the URI policy should be valid");

    assert_eq!(policy.uri().path_policy(), UriPathPolicy::Preserve);
    assert_eq!(policy.uri().fragment_policy(), UriFragmentPolicy::Preserve,);
}
/// Verifies invalid field names fail at the setter that receives them.
#[test]
fn test_redaction_policy_builder_rejects_invalid_field_immediately() {
    let mut builder = RedactionPolicy::builder();
    assert_eq!(
        builder.fields().raise("---", Sensitivity::High).err(),
        Some(PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules,
        }),
    );
}

/// Verifies invalid mask policies fail at the setter that receives them.
#[test]
fn test_redaction_policy_builder_rejects_invalid_mask_immediately() {
    let mut builder = RedactionPolicy::builder();
    assert_eq!(
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(""))
            .err(),
        Some(PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::Rules,
            level: Sensitivity::Secret,
        }),
    );
}

/// Verifies the builder installs a configured field sensitivity.
#[test]
fn test_redaction_policy_builder_builds_configured_rule() {
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .disable_floor()
        .raise("tenant_secret", Sensitivity::High)
        .expect("the test builder input should be valid");
    let policy = builder
        .build()
        .expect("the configured rule should be valid");

    assert_eq!(
        policy.sensitivity_for("tenant_secret"),
        Some(Sensitivity::High),
    );
}

/// Verifies a diagnostic budget is a first-class immutable policy setting.
#[test]
fn test_redaction_policy_builder_preserves_diagnostic_budget() {
    let budget =
        InputOutputLimit::new(128, 256).expect("the test budget is valid");
    let mut builder = RedactionPolicy::builder();
    builder.limits().diagnostic_event(budget);
    let policy = builder.build().expect("the policy should build");

    assert_eq!(policy.limits().diagnostic_event(), budget);
    assert_eq!(
        RedactionPolicy::builder_from(&policy)
            .build()
            .expect("copied policy should build"),
        policy,
    );
}

/// Verifies the builder preserves the root and array scalar JSON policy.
#[cfg(feature = "json")]
#[test]
fn test_redaction_policy_builder_preserves_unkeyed_json_policy() {
    let policy = RedactionPolicy::builder()
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::Redact)
        .build()
        .expect("the JSON policy should build");

    assert_eq!(
        policy.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::Redact,
    );
    assert_eq!(
        RedactionPolicy::builder_from(&policy)
            .build()
            .expect("the copied JSON policy should build")
            .unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::Redact,
    );
}

/// Verifies copied policies can revoke inherited exact and suffix allow rules.
#[test]
fn test_redaction_policy_builder_removes_inherited_allow_rules() {
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .disable_floor()
        .raise("access_token", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .raise("session_token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .allow_exact("access_token")
        .expect("the test builder input should be valid")
        .allow_suffix("session_token")
        .expect("the test builder input should be valid");
    let base = builder.build().expect("the base policy should be valid");
    let mut builder = RedactionPolicy::builder_from(&base);
    builder
        .fields()
        .remove_allow_exact("access-token")
        .expect("the test builder input should be valid")
        .remove_allow_suffix("session-token")
        .expect("the test builder input should be valid");
    let policy = builder.build().expect("the rebuilt policy should be valid");

    assert_eq!(
        policy.sensitivity_for("access_token"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
}

/// Verifies one operation removes every inherited allow rule.
#[test]
fn test_redaction_policy_builder_clears_inherited_allow_rules() {
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .disable_floor()
        .raise("access_token", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .raise("session_token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .allow_exact("access_token")
        .expect("the test builder input should be valid")
        .allow_suffix("session_token")
        .expect("the test builder input should be valid");
    let base = builder.build().expect("the base policy should be valid");
    let mut builder = RedactionPolicy::builder_from(&base);
    builder.fields().clear_allow_rules();
    let policy = builder.build().expect("the rebuilt policy should be valid");

    assert_eq!(
        policy.sensitivity_for("access_token"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression tests for bounded mask rendering.

#[cfg(feature = "http")]
use qubit_redact::{
    MaskPolicy,
    RedactionPolicy,
    Sensitivity,
    http::{
        BodyBudget,
        BodyCapture,
        HttpFieldContext,
        HttpRedactionPolicy,
        HttpRedactor,
    },
};

/// Redacts one sensitive JSON value with the supplied mask policy.
#[cfg(feature = "http")]
fn redact_json_value(
    mask: MaskPolicy,
    value: &str,
    max_output: usize,
) -> String {
    let body_policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("password", Sensitivity::Secret)
        .mask(Sensitivity::Secret, mask.clone())
        .build()
        .expect("the body policy is valid");
    let policy = HttpRedactionPolicy::builder()
        .rules(HttpFieldContext::Body, body_policy.rules().clone())
        .mask(Sensitivity::Secret, mask)
        .body_budget(
            BodyBudget::new(4096, max_output).expect("the budget is valid"),
        )
        .build()
        .expect("the HTTP policy is valid");
    let body = format!(r#"{{"password":"{value}"}}"#);
    HttpRedactor::new(policy)
        .redact_body(
            BodyCapture::complete(body.as_bytes()),
            Some(&http::HeaderValue::from_static("application/json")),
        )
        .to_string()
}

/// Verifies an amplified fixed replacement cannot exceed the body budget.
#[cfg(feature = "http")]
#[test]
fn test_fixed_mask_respects_output_budget() {
    let replacement = "x".repeat(1024 * 1024);
    let body_policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("password", Sensitivity::Secret)
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .build()
        .expect("the body policy is valid");
    let policy = HttpRedactionPolicy::builder()
        .rules(HttpFieldContext::Body, body_policy.rules().clone())
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .body_budget(BodyBudget::new(4096, 64).expect("the budget is valid"))
        .build()
        .expect("the HTTP policy is valid");
    let result = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete(br#"{"password":"secret"}"#),
        Some(&http::HeaderValue::from_static("application/json")),
    );
    let rendered = result.to_string();

    assert!(rendered.len() <= 64, "{rendered}");
    assert!(rendered.ends_with("<truncated>"), "{rendered}");
    assert!(!rendered.contains("secret"), "{rendered}");
}

/// Verifies bounded masking retains valid UTF-8 when a mask is split.
#[cfg(feature = "http")]
#[test]
fn test_fixed_unicode_mask_uses_valid_utf8_prefix() {
    let replacement = "你".repeat(100);
    let rendered =
        redact_json_value(MaskPolicy::fixed(&replacement), "secret", 17);

    assert_eq!(rendered, r#"{"pass<truncated>"#);
}

/// Verifies every bounded mask strategy preserves its masking semantics.
#[cfg(feature = "http")]
#[test]
fn test_bounded_mask_strategies_cover_short_and_retained_values() {
    let cases = [
        (MaskPolicy::fixed("****"), "", r#"{"password":""}"#),
        (
            MaskPolicy::preserve_edges(1, 1, "****", 4),
            "abcd",
            r#"{"password":"****"}"#,
        ),
        (
            MaskPolicy::preserve_edges(3, 3, "****", 0),
            "abcde",
            r#"{"password":"****"}"#,
        ),
        (
            MaskPolicy::preserve_edges(1, 1, "****", 0),
            "abcdef",
            r#"{"password":"a****f"}"#,
        ),
        (
            MaskPolicy::preserve_edges(0, 0, "****", 0),
            "abcdef",
            r#"{"password":"****"}"#,
        ),
        (
            MaskPolicy::preserve_suffix(1, "****", 4),
            "abcd",
            r#"{"password":"****"}"#,
        ),
        (
            MaskPolicy::preserve_suffix(5, "****", 0),
            "abcde",
            r#"{"password":"****"}"#,
        ),
        (
            MaskPolicy::preserve_suffix(2, "****", 0),
            "abcdef",
            r#"{"password":"****ef"}"#,
        ),
        (
            MaskPolicy::preserve_suffix(0, "****", 0),
            "abcdef",
            r#"{"password":"****"}"#,
        ),
        (MaskPolicy::empty(), "abcdef", r#"{"password":""}"#),
    ];

    for (mask, value, expected) in cases {
        assert_eq!(redact_json_value(mask, value, 128), expected);
    }
}

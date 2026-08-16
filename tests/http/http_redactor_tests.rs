// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use http::HeaderMap;
use http::HeaderValue;
use proptest::collection;
use proptest::prelude::any;
use proptest::prelude::prop_assert;
use proptest::prelude::proptest;
use qubit_redact::InputOutputLimit;
use qubit_redact::JsonDepthLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::MaskingPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::BodyBudget;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::BodyRedactionReason;
use qubit_redact::formats::http::BodyRedactionStatus;
use qubit_redact::formats::http::HttpRedactor;
use qubit_redact::formats::http::TextBodyPolicy;
use qubit_redact::formats::http::UnkeyedJsonValuePolicy;
use url::Url;
/// Builds an HTTP redactor with explicit finite body limits.
fn redactor_with_budget(input: usize, output: usize) -> HttpRedactor {
    let budget = BodyBudget::builder()
        .max_input_bytes(input)
        .max_output_bytes(output)
        .build()
        .expect("test budgets satisfy the public lower bounds");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().http_body(budget);
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    HttpRedactor::new(policy)
}

/// Verifies that http redactor covers url headers and body.
#[test]
fn test_http_redactor_covers_url_headers_and_body() {
    let redactor = HttpRedactor::new(RedactionPolicy::strict());
    let url =
        Url::parse("https://user:secret@example.test/private?api_key=raw")
            .expect("the test URL is valid");
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw"));

    let redacted_url = redactor.redact_url(&url);
    let redacted_headers = redactor.redact_headers(&headers);
    let redacted_body = redactor.redact_body(
        BodyCapture::complete(br#"{"password":"raw"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!redacted_url.as_ref().contains("secret"));
    assert!(!redacted_url.as_ref().contains("raw"));
    assert!(!redacted_headers.to_string().contains("Bearer raw"));
    assert!(!redacted_body.to_string().contains("raw"));
    assert_eq!(
        redacted_body.log_safe_text().as_ref(),
        redacted_body.to_string()
    );
    let rendered = redacted_body.to_string();
    assert_eq!(redacted_body.into_log_safe_text().as_ref(), rendered);
}

/// Verifies that body output budget applies after control escaping.
#[test]
fn test_body_output_budget_applies_after_control_escaping() {
    let redactor = redactor_with_budget(64, 16);
    let body = redactor.redact_body(
        BodyCapture::complete(b"a\nb\nc\nd\ne\nf\ng"),
        Some(&HeaderValue::from_static("text/plain")),
    );
    let rendered = body.to_string();

    assert_eq!(rendered, "a\\nb<truncated>");
    assert!(!rendered.ends_with("\\<truncated>"));
    assert_eq!(body.completion(), RedactionCompletion::Truncated);
}

/// Verifies that minimum output budget is exact marker.
#[test]
fn test_minimum_output_budget_is_exact_marker() {
    let redactor = redactor_with_budget(64, BodyBudget::MIN_OUTPUT_BYTES);
    let body = redactor.redact_body(
        BodyCapture::complete(b"payload larger than marker"),
        Some(&HeaderValue::from_static("text/plain")),
    );

    assert_eq!(body.to_string(), "<truncated>");
    assert_eq!(body.to_string().len(), BodyBudget::MIN_OUTPUT_BYTES);
}

/// Verifies that output truncation preserves multibyte utf8 boundary.
#[test]
fn test_output_truncation_preserves_multibyte_utf8_boundary() {
    let redactor = redactor_with_budget(64, 14);
    let body = redactor.redact_body(
        BodyCapture::complete("你好吗世界".as_bytes()),
        Some(&HeaderValue::from_static("text/plain")),
    );

    assert_eq!(body.to_string(), "你<truncated>");
    assert_eq!(body.to_string().len(), 14);
}

/// Verifies that source truncation is reported even when payload fits.
#[test]
fn test_source_truncation_is_reported_even_when_payload_fits() {
    let redactor = redactor_with_budget(64, 64);
    let capture = BodyCapture::truncated(b"ok", 9)
        .expect("the declared source length exceeds the captured prefix");
    let body = redactor
        .redact_body(capture, Some(&HeaderValue::from_static("text/plain")));

    assert_eq!(body.captured_len(), 2);
    assert_eq!(body.source_len(), Some(9));
    assert_eq!(body.omitted_len(), Some(7));
    assert_eq!(body.completion(), RedactionCompletion::Truncated);
    assert_eq!(body.to_string(), "ok<truncated>");
}

/// Verifies that input budget metadata is exact and output is bounded.
#[test]
fn test_input_budget_metadata_is_exact_and_output_is_bounded() {
    let redactor = redactor_with_budget(4, 15);
    let body = redactor.redact_body(
        BodyCapture::complete("abcdef".as_bytes()),
        Some(&HeaderValue::from_static("text/plain")),
    );

    assert_eq!(body.captured_len(), 4);
    assert_eq!(body.source_len(), Some(6));
    assert_eq!(body.omitted_len(), Some(2));
    assert_eq!(body.completion(), RedactionCompletion::Truncated);
    assert!(body.to_string().len() <= 15);
    assert!(body.to_string().ends_with("<truncated>"));
}

/// Verifies that native sensitive header wins over allow rule.
#[test]
fn test_native_sensitive_header_wins_over_allow_rule() {
    let allowed = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .allow_exact("x-visible")
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the allow-only test policy is valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .header()
        .replace_rules(allowed.rules().clone());
    let policy = builder
        .build()
        .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let mut value = HeaderValue::from_static("raw-secret");
    value.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert("x-visible", value);

    assert!(
        !redactor
            .redact_headers(&headers)
            .to_string()
            .contains("raw-secret")
    );
}

/// Verifies that structured body status and fail closed cases.
#[test]
fn test_structured_body_status_and_fail_closed_cases() {
    let redactor = HttpRedactor::new(RedactionPolicy::strict());
    let json_type = HeaderValue::from_static("application/json");
    let malformed = redactor.redact_body(
        BodyCapture::complete(br#"{"password":"secret""#),
        Some(&json_type),
    );
    let scalar = redactor
        .redact_body(BodyCapture::complete(br#""secret""#), Some(&json_type));

    assert_eq!(
        malformed.status(),
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson,)
    );
    assert!(!malformed.to_string().contains("secret"));
    assert!(!scalar.to_string().contains("secret"));
}

/// Verifies that multipart redacts file and sensitive field.
#[test]
fn test_multipart_redacts_file_and_sensitive_field() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nfile-secret\r\n--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nfield-secret\r\n--boundary--\r\n";
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");

    let result = HttpRedactor::default()
        .redact_body(BodyCapture::complete(body), Some(&content_type));

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
    assert!(result.to_string().contains("<redacted: file part>"));
    assert!(!result.to_string().contains("file-secret"));
    assert!(!result.to_string().contains("field-secret"));
}

/// Verifies that malformed and truncated multipart fail closed.
#[test]
fn test_malformed_and_truncated_multipart_fail_closed() {
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let malformed =
        b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret";
    let redactor = HttpRedactor::default();
    let complete = redactor
        .redact_body(BodyCapture::complete(malformed), Some(&content_type));
    let truncated = redactor.redact_body(
        BodyCapture::truncated_unknown(malformed),
        Some(&content_type),
    );

    assert!(!complete.to_string().contains("secret"));
    assert!(!truncated.to_string().contains("secret"));
    assert_eq!(truncated.completion(), RedactionCompletion::Truncated);
}

/// Verifies that multipart rejects invalid header parameter grammar.
#[test]
fn test_multipart_rejects_invalid_header_parameter_grammar() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let dispositions: [&[u8]; 11] = [
        b"form-data; bad name=value; name=note",
        b"form-data; name=note value",
        b"form-data; name=\"note\"junk",
        b"form-data; name=\"note\" junk \"",
        b"form-data; name=\"note\x00\"",
        b"form-data; name=\"note\x1b\"",
        b"form-data; name=\"note\\\x00\"",
        b"form-data; name=\"note\r\ninjected\"",
        b"form-data; name=note; size",
        b"form-data; name=note; size=1; size=2",
        b"form-data; name=note; name=password",
    ];

    for disposition in dispositions {
        let mut body = b"--b\r\nContent-Disposition: ".to_vec();
        body.extend_from_slice(disposition);
        body.extend_from_slice(
            b"\r\nContent-Type: text/plain\r\n\r\nraw-secret\r\n--b--\r\n",
        );

        let result = redactor
            .redact_body(BodyCapture::complete(&body), Some(&content_type));

        assert_eq!(
            result.status(),
            BodyRedactionStatus::Redacted(
                BodyRedactionReason::InvalidMultipart,
            ),
            "accepted malformed disposition: {:?}",
            String::from_utf8_lossy(disposition),
        );
        assert!(!result.to_string().contains("raw-secret"));
    }
}

/// Verifies that multipart form data requires exact disposition token.
#[test]
fn test_multipart_form_data_requires_exact_disposition_token() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let dispositions = ["form data; name=note", "attachment; name=note"];

    for disposition in dispositions {
        let body = format!(
            "--b\r\nContent-Disposition: {disposition}\r\nContent-Type: text/plain\r\n\r\npass-through-secret\r\n--b--\r\n",
        );
        let result = redactor.redact_body(
            BodyCapture::complete(body.as_bytes()),
            Some(&content_type),
        );

        assert_eq!(
            result.status(),
            BodyRedactionStatus::Redacted(
                BodyRedactionReason::InvalidMultipart,
            ),
        );
        assert!(!result.to_string().contains("pass-through-secret"));
    }
}

/// Verifies that multipart mixed allows missing but rejects malformed
/// disposition.
#[test]
fn test_multipart_mixed_allows_missing_but_rejects_malformed_disposition() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type = HeaderValue::from_static("multipart/mixed; boundary=b");
    let unnamed =
        b"--b\r\nContent-Type: text/plain\r\n\r\nunnamed-secret\r\n--b--\r\n";
    let named = b"--b\r\nContent-Disposition: attachment; name=note\r\nContent-Type: text/plain\r\n\r\nvisible\r\n--b--\r\n";
    let malformed = b"--b\r\nContent-Disposition: form data; name=note\r\nContent-Type: text/plain\r\n\r\nmalformed-secret\r\n--b--\r\n";

    let unnamed_result = redactor
        .redact_body(BodyCapture::complete(unnamed), Some(&content_type));
    let named_result =
        redactor.redact_body(BodyCapture::complete(named), Some(&content_type));
    let malformed_result = redactor
        .redact_body(BodyCapture::complete(malformed), Some(&content_type));

    assert_eq!(unnamed_result.status(), BodyRedactionStatus::Structured);
    assert!(
        unnamed_result
            .to_string()
            .contains("<unnamed>=<redacted: multipart part>")
    );
    assert!(!unnamed_result.to_string().contains("unnamed-secret"));
    assert_eq!(named_result.status(), BodyRedactionStatus::PassedThrough);
    assert!(named_result.to_string().contains("visible"));
    assert_eq!(
        malformed_result.status(),
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidMultipart,),
    );
    assert!(!malformed_result.to_string().contains("malformed-secret"));
}

/// Verifies that multipart boundary allows internal space but not trailing
/// space.
#[test]
fn test_multipart_boundary_allows_internal_space_but_not_trailing_space() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let body = b"--a b\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\n\r\nvisible\r\n--a b--\r\n";
    let valid_type =
        HeaderValue::from_static("multipart/form-data; boundary=\"a b\"");
    let invalid_type =
        HeaderValue::from_static("multipart/form-data; boundary=\"a \"");

    let valid =
        redactor.redact_body(BodyCapture::complete(body), Some(&valid_type));
    let invalid = redactor.redact_body(
        BodyCapture::complete(b"pass-through-secret"),
        Some(&invalid_type),
    );

    assert_eq!(valid.status(), BodyRedactionStatus::PassedThrough);
    assert!(valid.to_string().contains("visible"));
    assert_eq!(
        invalid.status(),
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidMultipart,),
    );
    assert!(!invalid.to_string().contains("pass-through-secret"));
}

/// Verifies that multipart rejects malformed part content type parameters.
#[test]
fn test_multipart_rejects_malformed_part_content_type_parameters() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let body = b"--b\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain; charset\r\n\r\npass-through-secret\r\n--b--\r\n";

    let result =
        redactor.redact_body(BodyCapture::complete(body), Some(&content_type));

    assert_eq!(
        result.status(),
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidMultipart,),
    );
    assert!(!result.to_string().contains("pass-through-secret"));
}

/// Verifies that body dispatch covers empty binary unsupported and invalid
/// content type.
#[test]
fn test_body_dispatch_covers_empty_binary_unsupported_and_invalid_content_type()
{
    let redactor = HttpRedactor::default();
    let empty = redactor.redact_body(BodyCapture::complete(b""), None);
    let binary = redactor.redact_body(BodyCapture::complete(b"\xff\xfe"), None);
    let unsupported =
        redactor.redact_body(BodyCapture::complete(b"visible-secret"), None);
    let invalid_type = HeaderValue::from_bytes(b"\xff")
        .expect("HTTP permits opaque non-UTF-8 header bytes");
    let invalid = redactor.redact_body(
        BodyCapture::complete(b"visible-secret"),
        Some(&invalid_type),
    );

    assert_eq!(empty.status(), BodyRedactionStatus::Empty);
    assert_eq!(empty.to_string(), "");
    assert_eq!(binary.status(), BodyRedactionStatus::Binary);
    assert_eq!(binary.to_string(), "<binary 2 bytes>");
    assert!(!unsupported.to_string().contains("visible-secret"));
    assert!(!invalid.to_string().contains("visible-secret"));
}

/// Verifies text Content-Type input selects parsers and rejects unsafe syntax.
#[test]
fn test_redact_body_with_content_type_text_dispatches_and_fails_closed() {
    let redactor = HttpRedactor::default();
    let structured = redactor.redact_body_with_content_type_text(
        BodyCapture::complete(br#"{"password":"raw"}"#),
        Some("application/json"),
    );
    let invalid = redactor.redact_body_with_content_type_text(
        BodyCapture::complete(b"visible-secret"),
        Some("text/plain\r\ninjected: true"),
    );

    assert!(!structured.to_string().contains("raw"));
    assert_eq!(
        invalid.status(),
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidContentType,),
    );
    assert!(!invalid.to_string().contains("visible-secret"));
}

/// Verifies oversized native and text Content-Type inputs fail closed before
/// parser classification.
#[test]
fn test_redact_body_rejects_content_type_beyond_diagnostic_input_budget() {
    let diagnostic_budget = InputOutputLimit::builder()
        .max_input_bytes(8)
        .max_output_bytes(64)
        .build()
        .expect("the small diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(diagnostic_budget);
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("the HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type = HeaderValue::from_bytes(b"text/plain; charset=utf-8")
        .expect("the test Content-Type should be valid HTTP header bytes");
    let native = redactor.redact_body(
        BodyCapture::complete(b"visible-secret"),
        Some(&content_type),
    );
    let text = redactor.redact_body_with_content_type_text(
        BodyCapture::complete(b"visible-secret"),
        Some("text/plain; charset=utf-8"),
    );

    for body in [native, text] {
        assert_eq!(
            body.status(),
            BodyRedactionStatus::Redacted(
                BodyRedactionReason::InvalidContentType,
            ),
        );
        assert!(!body.to_string().contains("visible-secret"));
    }
}

/// Verifies that ndjson and form body redaction cover valid and invalid inputs.
#[test]
fn test_ndjson_and_form_body_redaction_cover_valid_and_invalid_inputs() {
    let redactor = HttpRedactor::default();
    let ndjson_type = HeaderValue::from_static("application/x-ndjson");
    let form_type =
        HeaderValue::from_static("application/x-www-form-urlencoded");
    let ndjson = redactor.redact_body(
        BodyCapture::complete(
            b"{\"password\":\"secret\"}\n\n{\"mode\":\"ok\"}\n",
        ),
        Some(&ndjson_type),
    );
    let invalid_ndjson = redactor.redact_body(
        BodyCapture::complete(b"{\"password\":\"secret\""),
        Some(&ndjson_type),
    );
    let truncated_ndjson = redactor
        .redact_body(BodyCapture::truncated_unknown(b"{}"), Some(&ndjson_type));
    let form = redactor.redact_body(
        BodyCapture::complete(b"password=secret&mode=ok"),
        Some(&form_type),
    );
    let invalid_form = redactor.redact_body(
        BodyCapture::complete(b"password=secret&bad=%"),
        Some(&form_type),
    );
    let truncated_invalid_form = redactor.redact_body(
        BodyCapture::truncated_unknown(b"bad=%"),
        Some(&form_type),
    );
    let truncated_valid_prefix_form = redactor.redact_body(
        BodyCapture::truncated_unknown(b"note=partial"),
        Some(&form_type),
    );

    assert!(ndjson.to_string().contains("mode"));
    assert!(!ndjson.to_string().contains("secret"));
    assert!(!invalid_ndjson.to_string().contains("secret"));
    assert!(
        truncated_ndjson
            .to_string()
            .contains("invalid or truncated NDJSON")
    );
    assert!(!form.to_string().contains("secret"));
    assert!(!invalid_form.to_string().contains("secret"));
    assert!(
        truncated_invalid_form
            .to_string()
            .contains("invalid or truncated URL-encoded form")
    );
    assert!(
        truncated_valid_prefix_form
            .to_string()
            .contains("invalid or truncated URL-encoded form")
    );
    assert!(!truncated_valid_prefix_form.to_string().contains("partial"));
}

/// Verifies that json policy handles arrays non strings and unkeyed pass
/// through.
#[test]
fn test_json_policy_handles_arrays_non_strings_and_unkeyed_pass_through() {
    let mut masking_builder = MaskingPolicy::builder();
    masking_builder.secret(MaskPolicy::fixed("SECRET"));
    let masking = masking_builder.build();
    let body_policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("SECRET"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the test masking policy is valid");
    assert_eq!(body_policy.masking(), &masking);
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .body()
        .replace_rules(body_policy.rules().clone())
        .disable_floor();
    builder
        .http()
        .unkeyed_json(UnkeyedJsonValuePolicy::PassThrough);
    builder
        .fields()
        .mask(Sensitivity::Secret, MaskPolicy::fixed("SECRET"))
        .expect("the test mask policy should be valid");
    let policy = builder
        .build()
        .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let json_type = HeaderValue::from_static("application/json");
    let object = redactor.redact_body(
        BodyCapture::complete(
            br#"{"password":{"nested":true},"items":[{"password":42}]}"#,
        ),
        Some(&json_type),
    );
    let scalar =
        redactor.redact_body(BodyCapture::complete(b"42"), Some(&json_type));

    assert!(!object.to_string().contains("nested"));
    assert!(!object.to_string().contains("42"));
    assert_eq!(scalar.status(), BodyRedactionStatus::PassedThrough);
    assert_eq!(scalar.to_string(), "42");
}

/// Verifies allowed object-array scalars remain unkeyed when passed through.
#[test]
fn test_json_object_array_unkeyed_pass_through_reports_passed_through() {
    let mut builder = RedactionPolicy::strict().to_builder();
    builder
        .fields()
        .allow_exact("items")
        .expect("the object field should be valid");
    let policy = builder
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough)
        .build()
        .expect("the strict policy should build");
    let body = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete(br#"{"items":["visible",42,true]}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(body.status(), BodyRedactionStatus::PassedThrough);
    assert!(body.to_string().contains("visible"));
    assert!(body.to_string().contains("42"));
    assert!(body.to_string().contains("true"));
}

/// Verifies sensitive structured JSON values never feed their serialized form
/// into an edge-preserving mask.
#[test]
fn test_json_policy_masks_sensitive_non_strings_as_opaque_values() {
    let body_policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .mask(
                Sensitivity::Secret,
                MaskPolicy::preserve_edges(1, 1, "OPAQUE", 0),
            )
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the body policy should be valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .body()
        .replace_rules(body_policy.rules().clone())
        .disable_floor();
    builder
        .fields()
        .mask(
            Sensitivity::Secret,
            MaskPolicy::preserve_edges(1, 1, "OPAQUE", 0),
        )
        .expect("the test mask policy should be valid");
    let policy = builder.build().expect("the HTTP policy should be valid");
    let json_type = HeaderValue::from_static("application/json");

    let body = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete(br#"{"password":12345}"#),
        Some(&json_type),
    );

    assert_eq!(body.to_string(), r#"{"password":"OPAQUE"}"#);
}

/// Verifies HTTP JSON redaction inherits and enforces the body policy's depth
/// budget before rendering structured output.
#[test]
fn test_json_policy_fails_closed_at_depth_budget() {
    let budget = JsonDepthLimit::builder()
        .max_depth(1)
        .build()
        .expect("the depth budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().json_depth(budget);
        builder
    })
    .build()
    .expect("the HTTP policy should build");
    assert_eq!(policy.json_depth_limit(), budget);
    let redactor = HttpRedactor::new(policy);
    let body = redactor.redact_body(
        BodyCapture::complete(
            br#"{"shallow":"visible","nested":{"secret":"raw-depth-secret"}}"#,
        ),
        Some(&HeaderValue::from_static("application/json")),
    );
    let output = body.to_string();
    let value = serde_json::from_str::<serde_json::Value>(&output)
        .expect("depth-limited body output should remain valid JSON");

    assert_eq!(value["shallow"], "visible");
    assert_eq!(value["nested"], "<redacted>");
    assert!(!output.contains("raw-depth-secret"));
}

/// Verifies that multipart handles nested formats text unknown and empty.
#[test]
fn test_multipart_handles_nested_formats_text_unknown_and_empty() {
    let policy = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type =
        HeaderValue::from_static("multipart/mixed; boundary=boundary");
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"profile\"\r\nContent-Type: application/json\r\n\r\n{\"password\":\"secret\"}\r\n--boundary\r\nContent-Disposition: form-data; name=\"events\"\r\nContent-Type: application/x-ndjson\r\n\r\n{\"password\":\"secret\"}\n\r\n--boundary\r\nContent-Disposition: form-data; name=\"params\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npassword=secret\r\n--boundary\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--boundary\r\nContent-Disposition: form-data; name=\"opaque\"\r\nContent-Type: application/octet-stream\r\n\r\nsecret\r\n--boundary--\r\n";
    let result =
        redactor.redact_body(BodyCapture::complete(body), Some(&content_type));
    let empty = redactor.redact_body(
        BodyCapture::complete(b"--boundary--\r\n"),
        Some(&content_type),
    );

    assert!(!result.to_string().contains("secret"));
    assert!(result.to_string().contains("hello"));
    assert!(result.to_string().contains("multipart part"));
    assert_eq!(result.status(), BodyRedactionStatus::PassedThrough);
    assert_eq!(empty.to_string(), "<multipart>\\n</multipart>");
}

/// Verifies that body escapes unicode line and bidirectional controls.
#[test]
fn test_body_escapes_unicode_line_and_bidirectional_controls() {
    let redactor = redactor_with_budget(128, 128);
    let body = redactor.redact_body(
        BodyCapture::complete("first\u{2028}second\u{202e}tail".as_bytes()),
        Some(&HeaderValue::from_static("text/plain")),
    );

    assert_eq!(body.to_string(), r"first\u{2028}second\u{202e}tail");
    assert!(!body.to_string().contains('\u{2028}'));
    assert!(!body.to_string().contains('\u{202e}'));
}

/// Verifies that default redactor hides opaque text and truncated json.
#[test]
fn test_default_redactor_hides_opaque_text_and_truncated_json() {
    let redactor = HttpRedactor::default();
    let opaque = redactor.redact_body(
        BodyCapture::complete(b"plain-secret"),
        Some(&HeaderValue::from_static("text/plain")),
    );
    let truncated = redactor.redact_body(
        BodyCapture::truncated_unknown(br#"{"password":"secret""#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!opaque.to_string().contains("plain-secret"));
    assert!(!truncated.to_string().contains("secret"));
    assert!(truncated.to_string().contains("invalid or truncated JSON"));
}

/// Verifies that malformed content type grammar fails closed before dispatch.
#[test]
fn test_malformed_content_type_grammar_fails_closed_before_dispatch() {
    let redactor = redactor_with_budget(512, 512);
    let cases = [
        "text/plain garbage",
        "text/",
        "multipart/form-data garbage; boundary=b",
        "text/plain; charset",
        "text/plain; bad name=value",
        "text/plain; charset=utf 8",
    ];

    for content_type in cases {
        let content_type = HeaderValue::from_bytes(content_type.as_bytes())
            .expect("malformed grammar can still be valid HTTP header bytes");
        let result = redactor.redact_body(
            BodyCapture::complete(b"pass-through-secret"),
            Some(&content_type),
        );

        assert_eq!(
            result.status(),
            BodyRedactionStatus::Redacted(
                BodyRedactionReason::InvalidContentType,
            ),
        );
        assert!(!result.to_string().contains("pass-through-secret"));
    }
}

/// Verifies that ndjson unkeyed pass through reports passed through.
#[test]
fn test_ndjson_unkeyed_pass_through_reports_passed_through() {
    let policy = RedactionPolicy::builder()
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough)
        .build()
        .expect("HTTP redaction policy should be valid");
    let body = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete(b"\"visible\"\n42\n"),
        Some(&HeaderValue::from_static("application/x-ndjson")),
    );

    assert_eq!(body.status(), BodyRedactionStatus::PassedThrough);
    assert!(body.to_string().contains("visible"));
}

/// Verifies that multipart metadata and framing fail closed.
#[test]
fn test_multipart_metadata_and_framing_fail_closed() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let cases: [(&str, &[u8]); 8] = [
        (
            "duplicate disposition",
            b"--b\r\nContent-Disposition: form-data; name=note\r\nContent-Disposition: form-data; name=password\r\n\r\nsecret\r\n--b--\r\n",
        ),
        (
            "duplicate content type",
            b"--b\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\nContent-Type: application/json\r\n\r\nsecret\r\n--b--\r\n",
        ),
        (
            "valueless filename",
            b"--b\r\nContent-Disposition: form-data; name=note; filename\r\nContent-Type: text/plain\r\n\r\nsecret\r\n--b--\r\n",
        ),
        (
            "non-UTF-8 part header",
            b"--b\r\nContent-Disposition: form-data; name=\"note\xff\"\r\n\r\nsecret\r\n--b--\r\n",
        ),
        (
            "non-UTF-8 text part",
            b"--b\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\n\r\nsecret-\xff\r\n--b--\r\n",
        ),
        (
            "non-whitespace epilogue",
            b"--b\r\nContent-Disposition: form-data; name=password\r\n\r\nsecret\r\n--b--\r\nepilogue-secret",
        ),
        (
            "duplicate boundary",
            b"--b\r\n\r\n--b--\r\n",
        ),
        (
            "missing content disposition colon",
            b"--b\r\nContent-Disposition form-data; name=password\r\n\r\nsecret\r\n--b--\r\n",
        ),
    ];

    for (label, body) in cases {
        let selected_type = if label == "duplicate boundary" {
            HeaderValue::from_static(
                "multipart/form-data; boundary=b; boundary=other",
            )
        } else {
            content_type.clone()
        };
        let result = redactor
            .redact_body(BodyCapture::complete(body), Some(&selected_type));

        let expected_reason = if label == "duplicate boundary" {
            BodyRedactionReason::InvalidContentType
        } else {
            BodyRedactionReason::InvalidMultipart
        };
        assert_eq!(
            result.status(),
            BodyRedactionStatus::Redacted(expected_reason),
            "unexpected status for {label}",
        );
        assert!(!result.to_string().contains("secret"), "{label}");
    }
}

/// Verifies that multipart blank name extended filename and non utf8 file are
/// safe.
#[test]
fn test_multipart_blank_name_extended_filename_and_non_utf8_file_are_safe() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let body = b"--b\r\nContent-Disposition: form-data; name=\"   \"\r\nContent-Type: text/plain\r\n\r\nblank-secret\r\n--b\r\nContent-Disposition: form-data; name=attachment; filename*=UTF-8''secret.txt\r\nContent-Type: text/plain\r\n\r\nfile-secret\xff\r\n--b--\r\n";

    let result =
        redactor.redact_body(BodyCapture::complete(body), Some(&content_type));

    assert!(result.to_string().contains("<unnamed>"));
    assert!(result.to_string().contains("<redacted: file part>"));
    assert!(!result.to_string().contains("blank-secret"));
    assert!(!result.to_string().contains("file-secret"));
    assert!(!result.to_string().contains("secret.txt"));
}

/// Verifies that multipart accepts valid quoted pairs and unknown parameters.
#[test]
fn test_multipart_accepts_valid_quoted_pairs_and_unknown_parameters() {
    let content_type = HeaderValue::from_static(
        "multipart/form-data; charset=utf-8; boundary=\"b\"",
    );
    let body = b"--b\r\nContent-Disposition: form-data; name=note; size=6; filename=\"alice\\\";report.txt\"\r\n\r\nfile-secret\r\n--b--\r\n";

    let result = HttpRedactor::default()
        .redact_body(BodyCapture::complete(body), Some(&content_type));
    let unicode_body = "--b\r\nContent-Disposition: form-data; name=\"nøté\"; x=\"a\\ø\"\r\n\r\nvisible\r\n--b--\r\n";
    let unicode_result = HttpRedactor::default().redact_body(
        BodyCapture::complete(unicode_body.as_bytes()),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=b")),
    );

    assert!(result.to_string().contains("<redacted: file part>"));
    assert!(!result.to_string().contains("file-secret"));
    assert!(!result.to_string().contains("report.txt"));
    assert_eq!(unicode_result.status(), BodyRedactionStatus::Structured);
    assert!(unicode_result.to_string().contains("nøté"));
}

/// Verifies that multipart covers strict line and part policy branches.
#[test]
fn test_multipart_covers_strict_line_and_part_policy_branches() {
    let multipart_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let default_redactor = HttpRedactor::default();
    let structured = b"--b\r\nContent-Disposition: form-data; name=document\r\nContent-Type: application/json\r\n\r\n{\"password\":\"secret\"}\r\n--b\r\n \t\r\n--b\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\n\r\ntext-secret\r\n--b\r\nContent-Disposition: form-data; name=plain\r\n\r\nplain-secret\r\n--b--\r\n";
    let result = default_redactor
        .redact_body(BodyCapture::complete(structured), Some(&multipart_type));

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
    assert!(!result.to_string().contains("secret"));
    assert!(result.to_string().contains("multipart text part"));

    let pass_policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("HTTP redaction policy should be valid");
    let lf_only =
        b"--b\nContent-Disposition: form-data; name=plain\n\nvisible\n--b--\n";
    let passed = HttpRedactor::new(pass_policy)
        .redact_body(BodyCapture::complete(lf_only), Some(&multipart_type));

    assert_eq!(passed.status(), BodyRedactionStatus::PassedThrough);
    assert!(passed.to_string().contains("visible"));
}

/// Verifies that multipart invalid nested json and sensitive non utf8 fail
/// closed.
#[test]
fn test_multipart_invalid_nested_json_and_sensitive_non_utf8_fail_closed() {
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let bodies: [(&str, &[u8]); 2] = [
        (
            "invalid nested JSON",
            b"--b\r\nContent-Disposition: form-data; name=document\r\nContent-Type: application/json\r\n\r\n{\"password\":\"secret\"\r\n--b--\r\n",
        ),
        (
            "non-UTF-8 sensitive field",
            b"--b\r\nContent-Disposition: form-data; name=password\r\n\r\nsecret-\xff\r\n--b--\r\n",
        ),
    ];

    for (label, body) in bodies {
        let result = HttpRedactor::default()
            .redact_body(BodyCapture::complete(body), Some(&content_type));

        assert_eq!(
            result.status(),
            BodyRedactionStatus::Redacted(
                BodyRedactionReason::InvalidMultipart,
            ),
            "unexpected status for {label}",
        );
        assert!(!result.to_string().contains("secret"), "{label}");
    }
}

proptest! {
    /// Checks across generated inputs that http body never leaks structured secret.
    #[test]
    fn test_http_body_never_leaks_structured_secret(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let redactor = HttpRedactor::default();
        let cases = [
            (
                format!(r#"{{"password":"{secret}"}}"#),
                HeaderValue::from_static("application/json"),
            ),
            (
                format!("{{\"password\":\"{secret}\"}}\n"),
                HeaderValue::from_static("application/x-ndjson"),
            ),
            (
                format!("password={secret}"),
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            ),
            (
                format!("--b\r\nContent-Disposition: form-data; name=password\r\n\r\n{secret}\r\n--b--\r\n"),
                HeaderValue::from_static("multipart/form-data; boundary=b"),
            ),
        ];

        for (body, content_type) in cases {
            let result = redactor.redact_body(
                BodyCapture::complete(body.as_bytes()),
                Some(&content_type),
            );
            prop_assert!(!result.to_string().contains(&secret));
        }
    }

    /// Checks across generated inputs that http body handles arbitrary bytes without panicking.
    #[test]
    fn test_http_body_handles_arbitrary_bytes_without_panicking(
        body in collection::vec(any::<u8>(), 0..512),
    ) {
        let redactor = HttpRedactor::default();
        let content_types = [
            None,
            Some(HeaderValue::from_static("application/json")),
            Some(HeaderValue::from_static("application/x-ndjson")),
            Some(HeaderValue::from_static("application/x-www-form-urlencoded")),
            Some(HeaderValue::from_static("multipart/form-data; boundary=b")),
            Some(HeaderValue::from_static("text/plain")),
            Some(HeaderValue::from_static("application/octet-stream")),
        ];

        for content_type in &content_types {
            let _result = redactor.redact_body(
                BodyCapture::complete(&body),
                content_type.as_ref(),
            );
        }
    }
}

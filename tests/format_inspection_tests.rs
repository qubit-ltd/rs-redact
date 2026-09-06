// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public inspection contracts for every supported diagnostic format.

use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(feature = "http")]
use http::HeaderMap;
#[cfg(feature = "http")]
use http::HeaderValue;
#[cfg(feature = "uri")]
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionPolicy;
#[cfg(any(feature = "http", feature = "uri"))]
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;
#[cfg(feature = "http")]
use qubit_redact::formats::http::BodyCapture;
#[cfg(feature = "http")]
use qubit_redact::formats::http::TextBodyPolicy;
#[cfg(feature = "uri")]
use qubit_redact::formats::uri::UriFragmentPolicy;
#[cfg(feature = "uri")]
use qubit_redact::formats::uri::UriPathPolicy;
#[cfg(feature = "http")]
use url::form_urlencoded::byte_serialize;

/// Verifies scalar, argv, environment, and process inspection aggregate levels.
#[test]
fn test_inspect_core_formats_reports_highest_sensitivity() {
    let redactor = Redactor::standard();

    let field = redactor
        .inspect_field("password", "")
        .expect("field inspection should complete");
    assert_eq!(field.max_sensitivity(), Some(Sensitivity::Secret));

    let argv_items = [
        ArgvItem::sensitive(OsStr::new("low"), Sensitivity::Low),
        ArgvItem::sensitive(OsStr::new("secret"), Sensitivity::Secret),
    ];
    let argv = redactor
        .inspect_argv(argv_items.into_iter().filter(|_| true))
        .expect("argv inspection should complete");
    assert_eq!(argv.max_sensitivity(), Some(Sensitivity::Secret));
    let redacted_argv = redactor.redact_argv(argv_items.into_iter().filter(|_| true));
    assert!(!redacted_argv.text().as_str().contains("secret"));

    let environment = [(OsStr::new("PASSWORD"), OsStr::new("env-secret"))];
    let env = redactor
        .inspect_env_pairs(environment.into_iter().filter(|_| true))
        .expect("environment inspection should complete");
    assert_eq!(env.max_sensitivity(), Some(Sensitivity::Secret));
    let redacted_env = redactor.redact_env_pairs(environment.into_iter().filter(|_| true));
    assert!(!redacted_env.text().as_str().contains("env-secret"));

    let process = redactor
        .inspect_process(
            OsStr::new("program"),
            argv_items.into_iter().filter(|_| true),
            environment.into_iter().filter(|_| true),
        )
        .expect("process inspection should complete");
    assert_eq!(process.max_sensitivity(), Some(Sensitivity::Secret));

    let pair = redactor
        .inspect_env("PASSWORD", "env-secret")
        .expect("single environment inspection should complete");
    assert!(pair.contains_sensitive());

    let heuristic = redactor
        .inspect_heuristic_argv([ArgvItem::plain(OsStr::new("--password=secret"))])
        .expect("heuristic argv inspection should complete");
    assert_eq!(heuristic.max_sensitivity(), Some(Sensitivity::Secret));

    assert!(
        !redactor
            .inspect_argv([ArgvItem::plain(OsStr::new("visible"))])
            .expect("plain argv should be clear")
            .contains_sensitive()
    );
    assert!(
        !redactor
            .inspect_env("VISIBLE", "value")
            .expect("plain environment pair should be clear")
            .contains_sensitive()
    );
}

/// Inspection adapters stop at shared structural and input limits without
/// rendering or consuming an unbounded suffix.
#[test]
fn test_inspect_core_formats_report_shared_limit_failures() {
    let structural_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let structural = Redactor::new(structural_policy);
    assert!(
        structural
            .inspect_argv([ArgvItem::plain(OsStr::new("value"))])
            .is_err()
    );
    assert!(structural.inspect_env("VISIBLE", "value").is_err());

    let input_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let input = Redactor::new(input_policy);
    assert!(
        input
            .inspect_argv([ArgvItem::plain(OsStr::new("value"))])
            .is_err()
    );
    assert!(input.inspect_env("VISIBLE", "value").is_err());
}

/// Non-UTF-8 environment names are conservatively secret on Unix.
#[cfg(unix)]
#[test]
fn test_inspect_non_utf8_environment_name_is_secret() {
    let name = OsStr::from_bytes(&[0xFF]);
    let result = Redactor::standard()
        .inspect_env_pairs([(name, OsStr::new("value"))])
        .expect("non-UTF-8 name should be conclusively classified");
    assert_eq!(result.max_sensitivity(), Some(Sensitivity::Secret));
}

/// Verifies structured format inspection returns sensitivity without output.
#[cfg(all(feature = "json", feature = "http", feature = "uri"))]
#[test]
fn test_inspect_structured_formats_reports_sensitivity_without_rendering() {
    let redactor = Redactor::standard();

    let json = redactor
        .inspect_json(r#"{"visible":"ok","password":"secret"}"#)
        .expect("JSON inspection should complete");
    assert_eq!(json.max_sensitivity(), Some(Sensitivity::Secret));

    let http_url = redactor
        .inspect_http_url("https://user:password@example.test/?password=")
        .expect("HTTP URL inspection should complete");
    assert_eq!(http_url.max_sensitivity(), Some(Sensitivity::Secret));

    let mut headers = HeaderMap::new();
    let mut authorization = HeaderValue::from_static("Bearer secret");
    authorization.set_sensitive(true);
    let _ = headers.insert("authorization", authorization);
    let _ = headers.insert("cookie", HeaderValue::from_static("session=secret"));
    let header_inspection = redactor
        .inspect_http_headers(&headers)
        .expect("HTTP header inspection should complete");
    assert_eq!(
        header_inspection.max_sensitivity(),
        Some(Sensitivity::Secret)
    );

    let body = redactor
        .inspect_http_body(
            BodyCapture::complete(br#"{"password":"secret"}"#),
            Some(&HeaderValue::from_static("application/json")),
        )
        .expect("HTTP body inspection should complete");
    assert_eq!(body.max_sensitivity(), Some(Sensitivity::Secret));

    let uri = redactor
        .inspect_uri("s3://bucket/path?password=")
        .expect("URI inspection should complete");
    assert_eq!(uri.max_sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(uri.usage().output_bytes(), 0);
}

#[cfg(feature = "http")]
#[test]
fn test_inspect_multipart_classifies_nested_and_file_parts() {
    let body = concat!(
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"profile\"\r\n",
        "Content-Type: application/json\r\n\r\n",
        "{\"password\":\"nested-secret\"}\r\n",
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"avatar\"; filename=\"private.png\"\r\n\r\n",
        "file-secret\r\n",
        "--boundary--\r\n",
    );
    let result = Redactor::standard()
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(body.as_bytes()),
            Some("multipart/form-data; boundary=boundary"),
        )
        .expect("valid multipart should be completely inspected");

    assert_eq!(result.max_sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(result.usage().output_bytes(), 0);
}

/// Exercises each supported HTTP body classifier without publishing output.
#[cfg(feature = "http")]
#[test]
fn test_inspect_http_body_content_types_and_url_components() {
    let redactor = Redactor::standard();
    for (content_type, body) in [
        (
            "application/x-ndjson",
            b"{\"password\":\"one\"}\n\n{\"visible\":1}".as_slice(),
        ),
        (
            "application/x-www-form-urlencoded",
            b"password=secret&visible=ok".as_slice(),
        ),
        (
            "application/json",
            b"[\"unkeyed\",{\"password\":\"secret\"}]".as_slice(),
        ),
    ] {
        let inspection = redactor
            .inspect_http_body_with_content_type_text(
                BodyCapture::complete(body),
                Some(content_type),
            )
            .expect("supported body should be completely inspected");
        assert!(inspection.contains_sensitive());
    }

    let inferred = redactor
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(b"  {\"password\":\"secret\"}"),
            None,
        )
        .expect("JSON body should be inferred");
    assert!(inferred.contains_sensitive());

    let empty = redactor
        .inspect_http_body_with_content_type_text(BodyCapture::complete(b""), None)
        .expect("empty body should be clear");
    assert!(!empty.contains_sensitive());

    let url = redactor
        .inspect_http_url(
            "https://user:secret@example.test/private?redirect=https%3A%2F%2Fnested.test%2F%3Fpassword%3Dsecret#fragment",
        )
        .expect("nested URL should be inspected");
    assert!(url.contains_sensitive());

    let rendered = redactor.redact_http_body_with_content_type_text(
        BodyCapture::complete(b"password=secret"),
        Some("application/x-www-form-urlencoded"),
    );
    assert!(!rendered.text().as_str().contains("secret"));
}

/// Inspection errors expose only safe reasons, accounting, and diagnostics.
#[cfg(feature = "http")]
#[test]
fn test_inspect_http_rejects_incomplete_and_invalid_body_metadata() {
    let redactor = Redactor::standard();
    for error in [
        redactor
            .inspect_http_body_with_content_type_text(
                BodyCapture::truncated(b"partial", 100).expect("capture lengths should be valid"),
                Some("text/plain"),
            )
            .expect_err("truncated capture must be inconclusive"),
        redactor
            .inspect_http_body_with_content_type_text(
                BodyCapture::complete(b"password=%ZZ"),
                Some("application/x-www-form-urlencoded"),
            )
            .expect_err("invalid form must be inconclusive"),
        redactor
            .inspect_http_body_with_content_type_text(
                BodyCapture::complete(b"opaque"),
                Some("application/octet-stream"),
            )
            .expect_err("unsupported body must be inconclusive"),
    ] {
        assert_ne!(error.reasons(), Default::default());
        assert!(error.usage().presented_input_bytes() > 0);
        assert_eq!(error.to_string(), "redaction inspection was inconclusive");
    }
}

/// Covers native metadata failures and conservative text-body policy paths.
#[cfg(feature = "http")]
#[test]
fn test_inspect_http_native_metadata_and_text_policy_paths() {
    let redactor = Redactor::standard();
    let invalid_header =
        HeaderValue::from_bytes(&[0xFF]).expect("opaque header value should construct");
    let error = redactor
        .inspect_http_body(BodyCapture::complete(b"body"), Some(&invalid_header))
        .expect_err("non-text Content-Type must be inconclusive");
    assert!(
        error
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );
    assert!(
        !redactor
            .inspect_http_body(BodyCapture::complete(b""), None)
            .expect("empty body without metadata should be clear")
            .contains_sensitive()
    );

    let missing_boundary = redactor
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(b"body"),
            Some("multipart/form-data"),
        )
        .expect_err("multipart without boundary must be inconclusive");
    assert!(
        missing_boundary
            .reasons()
            .contains(RedactionReason::InvalidMultipart)
    );

    let pass_through = RedactionPolicy::builder()
        .http(|http| {
            http.text_body(TextBodyPolicy::PassThrough);
        })
        .expect("HTTP policy should be valid")
        .build()
        .expect("policy should build");
    let pass_through = Redactor::new(pass_through);
    let clear = pass_through
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(b"visible text"),
            Some("text/plain"),
        )
        .expect("UTF-8 text should pass through conclusively");
    assert!(!clear.contains_sensitive());
    assert!(
        pass_through
            .inspect_http_body_with_content_type_text(
                BodyCapture::complete(&[0xFF]),
                Some("text/plain"),
            )
            .is_err()
    );

    let strict_url = Redactor::strict()
        .inspect_http_url("https://example.test/private/path#fragment")
        .expect("strict URL inspection should complete");
    assert_eq!(strict_url.max_sensitivity(), Some(Sensitivity::High));

    let default_text = redactor
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(b"secret-looking text"),
            Some("text/plain"),
        )
        .expect("default text inspection should complete");
    assert_eq!(default_text.max_sensitivity(), Some(Sensitivity::Secret));

    for result in [
        redactor.inspect_http_url("not an absolute URL"),
        redactor.inspect_http_url("https://example.test/?value=%ZZ"),
    ] {
        assert!(result.is_err());
    }

    let mut nested = String::from("https://final.test/");
    for _ in 0..10 {
        let encoded = byte_serialize(nested.as_bytes()).collect::<String>();
        nested = format!("https://nested.test/?redirect={encoded}");
    }
    let nested_error = redactor
        .inspect_http_url(&nested)
        .expect_err("nested URL depth must be bounded");
    assert!(
        nested_error
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );

    for (content_type, body) in [
        (Some("not a content type"), b"body".as_slice()),
        (Some("application/json"), b"{".as_slice()),
        (Some("application/x-ndjson"), b"{}\n{".as_slice()),
        (None, b"opaque".as_slice()),
    ] {
        assert!(
            redactor
                .inspect_http_body_with_content_type_text(BodyCapture::complete(body), content_type,)
                .is_err()
        );
    }
}

/// HTTP inspection reports shared traversal exhaustion at each structured
/// adapter boundary.
#[cfg(feature = "http")]
#[test]
fn test_inspect_http_structures_honor_shared_node_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);

    let mut headers = HeaderMap::new();
    let _ = headers.insert("authorization", HeaderValue::from_static("secret"));
    assert!(redactor.inspect_http_headers(&headers).is_err());
    assert!(
        redactor
            .inspect_http_url("https://example.test/?password=secret")
            .is_err()
    );
}

/// JSON inspection traverses arrays, nested objects, and every scalar kind.
#[cfg(feature = "json")]
#[test]
fn test_inspect_json_traverses_nested_scalars() {
    let inspection = Redactor::strict()
        .inspect_json(r#"[null,true,42,"text",{"visible":{"password":"secret"}}]"#)
        .expect("nested JSON inspection should complete");
    assert_eq!(inspection.max_sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(inspection.usage().output_bytes(), 0);
}

/// Verifies invalid structured input cannot be reported as conclusively clear.
#[cfg(all(feature = "json", feature = "http", feature = "uri"))]
#[test]
fn test_inspect_invalid_structured_input_fails_closed() {
    let redactor = Redactor::standard();

    let json = redactor
        .inspect_json("{")
        .expect_err("invalid JSON must be inconclusive");
    assert!(json.reasons().contains(RedactionReason::InvalidJson));

    let uri = redactor
        .inspect_uri("not a URI")
        .expect_err("invalid URI must be inconclusive");
    assert!(uri.reasons().contains(RedactionReason::InvalidUri));

    let multipart = redactor
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(b"not-multipart"),
            Some("multipart/form-data; boundary=boundary"),
        )
        .expect_err("invalid multipart must be inconclusive");
    assert!(
        multipart
            .reasons()
            .contains(RedactionReason::InvalidMultipart)
    );
}

/// Classification is independent of rendered mask bytes and value emptiness.
#[cfg(feature = "uri")]
#[test]
fn test_inspect_uri_detects_identity_mask_and_empty_sensitive_value() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("tenant_payload");
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed("raw-secret"));
        })
        .expect("policy should be valid")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);

    for uri in [
        "s3://user:secret@bucket/key#private",
        "s3://bucket/key?tenant_payload=raw-secret",
        "s3://bucket/key?tenant_payload=",
    ] {
        assert_eq!(
            redactor
                .inspect_uri(uri)
                .expect("URI should be completely inspected")
                .max_sensitivity(),
            Some(Sensitivity::Secret),
        );
    }

    let error = redactor
        .inspect_uri("s3://user:%ZZ@bucket/key")
        .expect_err("invalid percent encoding must be inconclusive");
    assert!(error.reasons().contains(RedactionReason::InvalidUri));

    let strict = Redactor::strict()
        .inspect_uri("s3://user@bucket/private/path?flag&password=secret#fragment")
        .expect("strict URI should be completely inspected");
    assert_eq!(strict.max_sensitivity(), Some(Sensitivity::Secret));

    let uri_policy = RedactionPolicy::builder()
        .uri(|uri| {
            uri.path(UriPathPolicy::Redact)
                .fragment(UriFragmentPolicy::Redact);
        })
        .expect("URI policy should be valid")
        .build()
        .expect("policy should build");
    let path = Redactor::new(uri_policy)
        .inspect_uri("s3://bucket/private/path#fragment")
        .expect("URI path should be inspected");
    assert_eq!(path.max_sensitivity(), Some(Sensitivity::High));

    let username_only = Redactor::standard()
        .inspect_uri("s3://user@bucket/key")
        .expect("username-only URI should be inspected");
    assert_eq!(username_only.max_sensitivity(), None);

    for uri in ["s3://bucket/key?flag=%ZZ", "s3://bucket/key?%ZZ=value"] {
        let query_error = redactor
            .inspect_uri(uri)
            .expect_err("invalid query encoding must be inconclusive");
        assert!(query_error.reasons().contains(RedactionReason::InvalidUri));
    }
}

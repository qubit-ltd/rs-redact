// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

struct Example {
    secret: String,
    omitted: String,
}

impl Redact for Example {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Example", |fields| {
            fields.sensitive(Sensitivity::Secret, "secret", || &self.secret);
            fields.skipped("omitted", || &self.omitted);
        });
    }
}

#[test]
fn disabled_policy_preserves_configuration_through_builder() {
    let mut policy = RedactionPolicy::standard();
    assert!(!policy.is_disabled());
    assert!(policy.set_disabled(true).is_disabled());
    assert!(RedactionPolicy::disabled().is_disabled());
    assert!(
        policy
            .to_builder()
            .build()
            .expect("policy is valid")
            .is_disabled()
    );
    assert!(!policy.set_disabled(false).is_disabled());
}

#[test]
fn disabled_policy_outputs_scalar_and_domain_values_without_redaction() {
    let output = Redactor::new(RedactionPolicy::disabled()).redact_field("password", "raw-secret");
    assert!(output.text().as_str().contains("raw-secret"));
    assert!(output.summary().is_redaction_disabled());

    let value = Example {
        secret: "raw-secret".into(),
        omitted: "restored".into(),
    };
    let output = Redactor::new(RedactionPolicy::disabled()).redact(&value);
    assert!(output.text().as_str().contains("raw-secret"));
    assert!(output.text().as_str().contains("restored"));
    assert!(output.summary().is_redaction_disabled());
}

#[test]
fn disabled_inspection_is_explicit() {
    let inspection = Redactor::new(RedactionPolicy::disabled())
        .inspect_field("password", "raw-secret")
        .expect("disabled inspection remains conclusive");
    assert!(inspection.is_redaction_disabled());
}

#[test]
fn disabled_policy_restores_argv_env_and_process_values() {
    use qubit_redact::formats::argv::ArgvItem;

    let redactor = Redactor::new(RedactionPolicy::disabled());
    let argv = redactor.redact_heuristic_argv([
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::sensitive(OsStr::new("argv-secret"), Sensitivity::Secret),
    ]);
    assert!(argv.text().as_str().contains("argv-secret"));

    let environment = redactor.redact_env("PASSWORD", "env-secret");
    assert!(environment.text().as_str().contains("env-secret"));

    let process = redactor.redact_process(
        OsStr::new("client"),
        [
            ArgvItem::plain(OsStr::new("--token")),
            ArgvItem::plain(OsStr::new("process-secret")),
        ],
        [(OsStr::new("API_KEY"), OsStr::new("process-env-secret"))],
    );
    assert!(process.text().as_str().contains("process-secret"));
    assert!(process.text().as_str().contains("process-env-secret"));
}

#[cfg(feature = "json")]
#[test]
fn disabled_policy_restores_json_text_without_validation() {
    let output =
        Redactor::new(RedactionPolicy::disabled()).redact_json("not valid JSON: raw-secret");
    assert_eq!(output.text().as_str(), "not valid JSON: raw-secret");
}

#[cfg(feature = "uri")]
#[test]
fn disabled_policy_restores_uri_components() {
    let input = "https://user:password@example.test/private/path?token=uri-secret#fragment-secret";
    let output = Redactor::new(RedactionPolicy::disabled()).redact_uri(input);
    assert_eq!(output.text().as_str(), input);
}

#[cfg(feature = "http")]
#[test]
fn disabled_policy_restores_http_url_headers_and_body() {
    use http::HeaderMap;
    use http::HeaderValue;
    use qubit_redact::formats::http::BodyCapture;

    let redactor = Redactor::new(RedactionPolicy::disabled());
    let url = "https://example.test/private?token=http-secret#fragment-secret";
    assert_eq!(redactor.redact_http_url(url).text().as_str(), url);

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer header-secret"),
    );
    let header_output = redactor.redact_http_headers(&headers);
    assert!(
        header_output
            .text()
            .as_str()
            .contains("Bearer header-secret")
    );

    let body = br#"{"token":"body-secret"}"#;
    let body_output = redactor.redact_http_body(
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("application/json")),
    );
    assert!(body_output.text().as_str().contains("body-secret"));
}

#[cfg(feature = "http")]
#[test]
fn test_disabled_policy_restores_invalid_http_json_without_validation() {
    use http::HeaderValue;
    use qubit_redact::formats::http::BodyCapture;

    let body = b"not valid JSON: raw-secret";
    let output = Redactor::new(RedactionPolicy::disabled()).redact_http_body(
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(output.text().as_str(), "not valid JSON: raw-secret");
    assert!(output.summary().is_redaction_disabled());
}

#[cfg(feature = "http")]
#[test]
fn test_disabled_policy_restores_other_invalid_structured_http_bodies() {
    use http::HeaderValue;
    use qubit_redact::formats::http::BodyCapture;

    let composer = Redactor::new(RedactionPolicy::disabled())
        .text_composer()
        .http(|http| {
            let _ = http.body_with_content_type_text(
                BodyCapture::complete(b"password=%ZZraw-secret"),
                Some("application/x-www-form-urlencoded"),
            );
        })
        .finish();
    assert_eq!(composer.text().as_str(), "password=%ZZraw-secret");
    assert!(composer.summary().is_redaction_disabled());

    let mut batch = Redactor::new(RedactionPolicy::disabled()).batch();
    let ndjson = batch.redact_http_body(
        BodyCapture::complete(b"not-json: raw-ndjson-secret"),
        Some(&HeaderValue::from_static("application/x-ndjson")),
    );
    let multipart = batch.redact_http_body(
        BodyCapture::complete(b"malformed multipart raw-secret"),
        Some(&HeaderValue::from_static("multipart/form-data")),
    );
    let output = batch.finish();

    assert_eq!(
        output
            .resolve(ndjson)
            .expect("NDJSON handle")
            .text()
            .as_str(),
        "not-json: raw-ndjson-secret",
    );
    assert_eq!(
        output
            .resolve(multipart)
            .expect("multipart handle")
            .text()
            .as_str(),
        "malformed multipart raw-secret",
    );
    assert!(output.summary().is_redaction_disabled());
}

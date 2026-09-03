// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::ffi::OsStr;

use qubit_redact::Redact;
#[cfg(feature = "json")]
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

struct Example {
    secret: String,
    omitted: String,
}

/// Domain value that writes one field through the selected disabled-mode path.
enum SingleDisabledField {
    Unredacted,
    Sensitive,
    #[cfg(feature = "json")]
    JsonUnredacted,
    #[cfg(feature = "json")]
    Json,
}

impl Redact for SingleDisabledField {
    /// Writes exactly one record field so its structural charge is observable.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("SingleDisabledField", |fields| match self {
            Self::Unredacted => {
                fields.unredacted("value", || "raw-secret");
            }
            Self::Sensitive => {
                fields.sensitive(Sensitivity::Secret, "value", || "raw-secret");
            }
            #[cfg(feature = "json")]
            Self::JsonUnredacted => {
                fields.unredacted("value", || r#"{"token":"raw-secret"}"#);
            }
            #[cfg(feature = "json")]
            Self::Json => {
                fields.json("value", r#"{"token":"raw-secret"}"#);
            }
        });
    }
}

/// Builds a disabled policy with an exact domain-node limit.
fn disabled_node_policy(maximum: usize) -> RedactionPolicy {
    let mut policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(maximum);
        })
        .expect("the domain-node limit should be valid")
        .build()
        .expect("the disabled regression policy should build");
    let _ = policy.set_disabled(true);
    policy
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
    assert!(policy.to_builder().build().expect("policy is valid").is_disabled());
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

/// A disabled sensitive field must consume the same structural budget as an
/// explicitly unredacted field.
#[test]
fn test_disabled_domain_field_sensitive_is_admitted_once() {
    for maximum in [1, 2] {
        let redactor = Redactor::new(disabled_node_policy(maximum));
        let baseline = redactor.redact(&SingleDisabledField::Unredacted);
        let sensitive = redactor.redact(&SingleDisabledField::Sensitive);

        assert_eq!(sensitive.text().as_str(), baseline.text().as_str());
        assert_eq!(sensitive.summary(), baseline.summary());
        if maximum == 2 {
            assert!(sensitive.text().as_str().contains("raw-secret"));
        }
    }
}

/// A disabled JSON field must not spend a second domain node while restoring
/// its original text.
#[cfg(feature = "json")]
#[test]
fn test_disabled_domain_field_json_is_admitted_once() {
    for maximum in [1, 2] {
        let redactor = Redactor::new(disabled_node_policy(maximum));
        let baseline = redactor.redact(&SingleDisabledField::JsonUnredacted);
        let output = redactor.redact(&SingleDisabledField::Json);

        assert_eq!(output.text().as_str(), baseline.text().as_str());
        assert_eq!(output.summary(), baseline.summary());
        if maximum == 2 {
            assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
            assert_eq!(output.summary().usage().visited_nodes(), 2);
            assert!(output.text().as_str().contains(r#"{\"token\":\"raw-secret\"}"#));
        }
    }
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
    let output = Redactor::new(RedactionPolicy::disabled()).redact_json("not valid JSON: raw-secret");
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
    headers.insert("authorization", HeaderValue::from_static("Bearer header-secret"));
    let header_output = redactor.redact_http_headers(&headers);
    assert!(header_output.text().as_str().contains("Bearer header-secret"));

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
    let output = batch.finish_for_diagnostics("<redaction incomplete>");

    assert_eq!(output.text(ndjson).as_str(), "not-json: raw-ndjson-secret",);
    assert_eq!(output.text(multipart).as_str(), "malformed multipart raw-secret",);
    assert!(output.summary().is_redaction_disabled());
}

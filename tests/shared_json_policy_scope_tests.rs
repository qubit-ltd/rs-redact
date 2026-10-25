// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(feature = "http")]

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::UnkeyedJsonValuePolicy;
use qubit_redact::formats::http::BodyCapture;

#[test]
fn test_unkeyed_json_pass_through_scope_and_strict_contrast() {
    let pass_through = Redactor::new(
        RedactionPolicy::strict()
            .to_builder()
            .fields(|fields| {
                fields.allow_exact("item");
            })
            .expect("multipart part policy should be valid")
            .http(|http| {
                http.unkeyed_json(UnkeyedJsonValuePolicy::PassThrough);
            })
            .expect("HTTP policy configuration should be valid")
            .build()
            .expect("HTTP policy should be valid"),
    );
    let strict = Redactor::strict();

    for body in [r#""visible-root""#, r#"["visible-array",23,true]"#] {
        let output = pass_through.redact_json(body);
        assert!(output.text().as_str().contains("visible"));
        assert!(
            !pass_through
                .inspect_json(body)
                .expect("pass-through inspection should be conclusive")
                .contains_sensitive()
        );

        let strict_output = strict.redact_json(body);
        assert!(!strict_output.text().as_str().contains("visible"));
        assert!(
            strict
                .inspect_json(body)
                .expect("strict inspection should be conclusive")
                .contains_sensitive()
        );
    }

    for (content_type, body, visible) in [
        ("application/json", r#""visible-root""#, "visible-root"),
        ("application/json", r#"["visible-array",23,true]"#, "visible-array"),
        (
            "application/x-ndjson",
            "\"visible-line\"\n[\"visible-record\",23]\n",
            "visible-line",
        ),
        (
            "multipart/form-data; boundary=x",
            "--x\r\nContent-Disposition: form-data; name=\"item\"\r\nContent-Type: application/json\r\n\r\n[\"visible-part\",23]\r\n--x--\r\n",
            "visible-part",
        ),
    ] {
        let capture = BodyCapture::complete(body.as_bytes());
        let output = pass_through.redact_http_body_with_content_type_text(capture, Some(content_type));
        assert!(
            output.text().as_str().contains(visible),
            "{content_type}: {}",
            output.text().as_str()
        );
        assert!(
            !pass_through
                .inspect_http_body_with_content_type_text(capture, Some(content_type))
                .expect("pass-through HTTP inspection should be conclusive")
                .contains_sensitive(),
            "{content_type}"
        );

        let strict_output = strict.redact_http_body_with_content_type_text(capture, Some(content_type));
        assert!(
            !strict_output.text().as_str().contains(visible),
            "{content_type}: {}",
            strict_output.text().as_str()
        );
        assert!(
            strict
                .inspect_http_body_with_content_type_text(capture, Some(content_type))
                .expect("strict HTTP inspection should be conclusive")
                .contains_sensitive(),
            "{content_type}"
        );
    }
}

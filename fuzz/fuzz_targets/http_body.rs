// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use std::fmt::Write;

use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use qubit_redact::http::{
    BodyCapture,
    HttpRedactor,
};

const FUZZ_SECRET: &str = "qubit-fuzz-secret-7f54a19c";

/// Encodes a bounded input prefix as lowercase hexadecimal text.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes used as structured non-secret noise.
///
/// # Returns
///
/// Hexadecimal text for at most the first 64 bytes.
#[must_use]
fn hexadecimal_prefix(data: &[u8]) -> String {
    let mut encoded = String::with_capacity(data.len().min(64) * 2);
    for byte in data.iter().take(64) {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

/// Verifies a known secret is removed from one valid structured HTTP body.
///
/// # Parameters
///
/// * `selector` - Chooses JSON, NDJSON, form, or multipart syntax.
/// * `data` - Fuzzer-provided bytes used as non-secret structured noise.
fn assert_structured_secret_is_redacted(selector: u8, data: &[u8]) {
    let noise = hexadecimal_prefix(data);
    let (body, content_type) = match selector % 7 {
        0 => (
            format!(r#"{{"noise":"{noise}","password":"{FUZZ_SECRET}"}}"#)
                .into_bytes(),
            HeaderValue::from_static("application/json"),
        ),
        1 => (
            format!(
                "{{\"noise\":\"{noise}\"}}\n{{\"password\":\"{FUZZ_SECRET}\"}}"
            )
            .into_bytes(),
            HeaderValue::from_static("application/x-ndjson"),
        ),
        2 => (
            format!("noise={noise}&password={FUZZ_SECRET}").into_bytes(),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ),
        3 => {
            let mut multipart = b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"fuzz.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
            multipart.extend_from_slice(data);
            multipart.extend_from_slice(
                format!(
                    "\r\n--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{FUZZ_SECRET}\r\n--boundary--\r\n"
                )
                .as_bytes(),
            );
            (
                multipart,
                HeaderValue::from_static(
                    "multipart/form-data; boundary=boundary",
                ),
            )
        }
        4 => (
            format!(r#""{FUZZ_SECRET}""#).into_bytes(),
            HeaderValue::from_static("application/json"),
        ),
        5 => (
            format!(r#"["{FUZZ_SECRET}"]"#).into_bytes(),
            HeaderValue::from_static("application/json"),
        ),
        _ => (
            format!("\"{FUZZ_SECRET}\"\n").into_bytes(),
            HeaderValue::from_static("application/x-ndjson"),
        ),
    };
    let result = HttpRedactor::default()
        .redact_body(BodyCapture::complete(&body), Some(&content_type));
    assert!(!result.log_safe_text().as_ref().contains(FUZZ_SECRET));
}

/// Verifies malformed structured bodies fail closed around a known secret.
///
/// # Parameters
///
/// * `selector` - Chooses one bounded malformed JSON, NDJSON, form, or
///   multipart body.
fn assert_malformed_structured_secret_is_redacted(selector: u8) {
    let (body, content_type) = match selector % 5 {
        0 => (
            format!(r#"{{"password":"{FUZZ_SECRET}""#).into_bytes(),
            HeaderValue::from_static("application/json"),
        ),
        1 => (
            format!(
                "{{\"noise\":\"visible\"}}\n{{\"password\":\"{FUZZ_SECRET}\""
            )
            .into_bytes(),
            HeaderValue::from_static("application/x-ndjson"),
        ),
        2 => (
            format!("password={FUZZ_SECRET}&noise=%").into_bytes(),
            HeaderValue::from_static(
                "application/x-www-form-urlencoded",
            ),
        ),
        3 => (
            format!(
                "--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{FUZZ_SECRET}"
            )
            .into_bytes(),
            HeaderValue::from_static(
                "multipart/form-data; boundary=boundary",
            ),
        ),
        _ => (
            format!(
                "--boundary\r\nContent-Disposition: form-data; name=\"password\"; name=\"note\"\r\n\r\n{FUZZ_SECRET}\r\n--boundary--\r\n"
            )
            .into_bytes(),
            HeaderValue::from_static(
                "multipart/form-data; boundary=boundary",
            ),
        ),
    };

    let result = HttpRedactor::default()
        .redact_body(BodyCapture::complete(&body), Some(&content_type));
    assert!(!result.log_safe_text().as_ref().contains(FUZZ_SECRET));
}

fuzz_target!(|data: &[u8]| {
    let [media_selector, source_selector, _options, body @ ..] = data else {
        return;
    };
    let content_types = [
        None,
        Some(HeaderValue::from_static("application/json")),
        Some(HeaderValue::from_static("application/x-ndjson")),
        Some(HeaderValue::from_static(
            "application/x-www-form-urlencoded",
        )),
        Some(HeaderValue::from_static(
            "multipart/form-data; boundary=boundary",
        )),
        Some(HeaderValue::from_static("text/plain")),
    ];
    let content_type =
        &content_types[usize::from(*media_selector) % content_types.len()];
    let capture = match source_selector % 3 {
        0 => BodyCapture::complete(body),
        1 => BodyCapture::truncated(
            body,
            Some(
                body.len()
                    .saturating_add(usize::from(*source_selector).max(1)),
            ),
        )
        .expect("constructed total exceeds captured bytes"),
        _ => BodyCapture::truncated(body, None)
            .expect("unknown truncated captures are valid"),
    };
    let redactor = HttpRedactor::default();
    let redact = || redactor.redact_body(capture, content_type.as_ref());

    let first = redact();
    let second = redact();
    assert_eq!(first, second);
    assert!(first.captured_len() <= body.len());
    if let Some(source_len) = first.source_len() {
        assert!(source_len >= first.captured_len());
    }
    assert_structured_secret_is_redacted(*media_selector, body);
    assert_malformed_structured_secret_is_redacted(*media_selector);
});

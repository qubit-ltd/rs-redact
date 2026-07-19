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
use qubit_sanitize::{
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
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
            format!(
                r#"{{"noise":"{noise}","password":"{FUZZ_SECRET}"}}"#
            )
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
            HeaderValue::from_static(
                "application/x-www-form-urlencoded",
            ),
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
    let result = HttpBodySanitizer::default().sanitize_body(
        &body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    assert!(!result.raw_content().contains(FUZZ_SECRET));
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

    let result = HttpBodySanitizer::default().sanitize_body(
        &body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    assert!(!result.raw_content().contains(FUZZ_SECRET));
}

fuzz_target!(|data: &[u8]| {
    let [media_selector, source_selector, options, body @ ..] = data else {
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
    let source_length = match source_selector % 3 {
        0 => BodySourceLength::Known(body.len()),
        1 => BodySourceLength::Known(
            body.len()
                .saturating_add(usize::from(*source_selector).max(1)),
        ),
        _ => BodySourceLength::UnknownTruncated,
    };
    let match_mode = if options & 2 == 0 {
        NameMatchMode::Exact
    } else {
        NameMatchMode::ExactOrSuffix
    };
    let sanitizer = HttpBodySanitizer::default();
    let sanitize = || {
        if options & 1 == 0 {
            sanitizer.sanitize_body(body, content_type.as_ref(), match_mode)
        } else {
            sanitizer.sanitize_body_preview(
                body,
                source_length,
                content_type.as_ref(),
                match_mode,
            )
        }
    };

    let first = sanitize();
    let second = sanitize();
    assert_eq!(first, second);
    assert_eq!(first.captured_len(), body.len());
    if let Some(source_len) = first.source_len() {
        assert!(source_len >= first.captured_len());
    }
    assert_structured_secret_is_redacted(*media_selector, body);
    assert_malformed_structured_secret_is_redacted(*media_selector);
});

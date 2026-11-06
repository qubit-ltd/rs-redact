// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression tests for Unicode-safe log output.

use std::panic::catch_unwind;

use http::HeaderValue;
use qubit_redact::RedactionCompletion;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;
use serde_json::json;
use serde_json::to_string;

use self::support::log_safety;

mod support;

#[test]
fn test_rejects_raw_unsafe_characters() {
    let controls = (0_u32..=0x9f)
        .filter(|n| *n < 0x20 || *n >= 0x7f)
        .map(|n| char::from_u32(n).expect("control scalar"));
    let bidi = ['\u{061c}', '\u{200e}', '\u{200f}']
        .into_iter()
        .chain((0x2028..=0x202e).map(|n| char::from_u32(n).unwrap()))
        .chain((0x2066..=0x2069).map(|n| char::from_u32(n).unwrap()));
    for c in controls.chain(bidi) {
        assert!(
            catch_unwind(|| {
                log_safety::assert_log_safe(&c.to_string());
            })
            .is_err(),
            "oracle accepted U+{:04X}",
            c as u32
        );
    }
}

#[test]
fn test_accepts_safe_text() {
    for text in ["", "ordinary 中文 😀", r"\n\u{61c}\u{200e}\u{200f}"] {
        log_safety::assert_log_safe(text);
    }
}

#[test]
fn test_formats_and_batches_escape_missing_bidi_characters() {
    let redactor = Redactor::standard();
    let json_type = HeaderValue::from_static("application/json");
    let multipart_type = HeaderValue::from_static("multipart/form-data; boundary=rr01");
    for c in ['\u{061c}', '\u{200e}', '\u{200f}'] {
        let json = to_string(&json!({
            "note": format!("rr01-visible{c}"), "password": "rr01-secret"
        }))
        .unwrap();
        let multipart = format!(
            "--rr01\r\nContent-Disposition: form-data; name=\"payload\"\r\nContent-Type: application/json\r\n\r\n{json}\r\n--rr01--\r\n"
        );
        let outputs = [
            redactor.redact_json(&json),
            redactor.redact_http_body(BodyCapture::complete(json.as_bytes()), Some(&json_type)),
            redactor.redact_http_body(BodyCapture::complete(multipart.as_bytes()), Some(&multipart_type)),
        ];
        for output in outputs {
            assert_eq!(
                output.summary().completion(),
                RedactionCompletion::Complete,
                "redaction did not complete"
            );
            let text = output.text().as_str();
            log_safety::assert_log_safe(text);
            assert!(text.contains("rr01-visible"), "visible sentinel was removed");
            assert!(!text.contains("rr01-secret"), "secret was published");
            assert!(!text.contains(c), "raw bidi character U+{:04X} was published", c as u32);
        }
        let mut batch = redactor.diagnostic_batch();
        let handles = [
            batch.redact_json(&json),
            batch.redact_http_body(BodyCapture::complete(json.as_bytes()), Some(&json_type)),
            batch.redact_http_body(BodyCapture::complete(multipart.as_bytes()), Some(&multipart_type)),
        ];
        let output = batch.finish();
        assert_eq!(
            output.summary().completion(),
            RedactionCompletion::Complete,
            "redaction did not complete"
        );
        for handle in handles {
            let text = output.text(handle).as_str();
            log_safety::assert_log_safe(text);
            assert!(text.contains("rr01-visible"), "visible sentinel was removed");
            assert!(!text.contains("rr01-secret"), "secret was published");
            assert!(!text.contains(c), "raw bidi character U+{:04X} was published", c as u32);
        }
    }
}

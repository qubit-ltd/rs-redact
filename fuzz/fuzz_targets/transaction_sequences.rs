// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use std::ffi::OsStr;

use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionHandleError;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::formats::http::BodyCapture;

/// Checks publication invariants shared by every completed transaction.
fn check_output(output: &qubit_redact::RedactionSessionOutput, output_limit: usize) {
    assert!(output.summary().usage().output_bytes() <= output_limit);
    assert!(output.text().as_str().len() <= output_limit);
    assert!(std::str::from_utf8(output.text().as_str().as_bytes()).is_ok());
}

// Exercises reusable session transaction boundaries with arbitrary operation
// sequences. Published output must remain UTF-8 and isolated from handles
// created by earlier transactions.
fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(4096)];
    let mut session = Redactor::standard().session();
    let output_limit = session.policy().limits().max_output_bytes();
    let mut pending_handle = None;
    let mut previous_handle = None;
    for chunk in data.chunks(8).take(128) {
        let selector = chunk.first().copied().unwrap_or_default();
        let value = String::from_utf8_lossy(chunk);
        match selector % 10 {
            0 => {
                let _ = session.literal("event=").field("name", &value);
            }
            1 => {
                pending_handle = Some(session.redact_field("password", &value));
            }
            2 => {
                let json = format!(r#"{{"password":"{selector}"}}"#);
                session.json(|adapter| {
                    adapter.text(&json);
                });
            }
            3 => {
                pending_handle = Some(session.redact_http_url("https://fuzz.example/?password=transaction-secret"));
            }
            4 => {
                pending_handle = Some(session.redact_uri("https://fuzz.example/?password=transaction-secret"));
            }
            5 => {
                let items = [ArgvItem::plain(OsStr::new("--password=transaction-secret"))];
                pending_handle = Some(session.redact_argv(items));
            }
            6 => {
                pending_handle = Some(session.redact_env("PASSWORD", &value));
            }
            7 => {
                let arguments = [ArgvItem::plain(OsStr::new("--password=transaction-secret"))];
                let variables = [(OsStr::new("PASSWORD"), OsStr::new("transaction-secret"))];
                pending_handle = Some(session.redact_process(OsStr::new("client"), arguments, variables));
            }
            8 => {
                let content_type = HeaderValue::from_static("application/json");
                pending_handle = Some(session.redact_http_body(
                    BodyCapture::complete(br#"{"password":"transaction-secret"}"#),
                    Some(&content_type),
                ));
            }
            _ => {
                let output = session.finish();
                check_output(&output, output_limit);
                if let Some(handle) = pending_handle.take() {
                    assert!(output.resolve(handle).is_ok());
                    previous_handle = Some(handle);
                }
                if let Some(handle) = previous_handle {
                    let next = session.finish();
                    check_output(&next, output_limit);
                    assert_eq!(next.resolve(handle), Err(RedactionHandleError::DifferentTransaction));
                    previous_handle = None;
                }
            }
        }
    }
    let output = session.finish();
    check_output(&output, output_limit);
    if let Some(handle) = pending_handle {
        assert!(output.resolve(handle).is_ok());
        previous_handle = Some(handle);
    }
    if let Some(handle) = previous_handle {
        let next = session.finish();
        check_output(&next, output_limit);
        assert_eq!(next.resolve(handle), Err(RedactionHandleError::DifferentTransaction));
    }
});

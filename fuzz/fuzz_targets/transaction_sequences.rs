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
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::formats::http::BodyCapture;

/// Checks publication invariants shared by every completed batch.
fn check_output(output: &qubit_redact::RedactionBatchOutput, output_limit: usize) {
    assert!(output.summary().usage().output_bytes() <= output_limit);
}

// Exercises batch publication boundaries with arbitrary operation sequences.
// A handle is valid only for the batch that created it.
fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(4096)];
    let output_limit = Redactor::standard().policy().limits().max_output_bytes();
    for chunk in data.chunks(8).take(128) {
        let selector = chunk.first().copied().unwrap_or_default();
        let value = String::from_utf8_lossy(chunk);
        let mut batch = Redactor::standard().batch();
        match selector % 10 {
            0 => {
                let handle = batch.redact_field("name", &value);
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            1 => {
                let handle = batch.redact_field("password", &value);
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            2 => {
                let json = format!(r#"{{"password":"{selector}"}}"#);
                let handle = batch.redact_json(&json);
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            3 => {
                let handle =
                    batch.redact_http_url("https://fuzz.example/?password=transaction-secret");
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            4 => {
                let handle = batch.redact_uri("https://fuzz.example/?password=transaction-secret");
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            5 => {
                let items = [ArgvItem::plain(OsStr::new("--password=transaction-secret"))];
                let handle = batch.redact_argv(items);
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            6 => {
                let handle = batch.redact_env("PASSWORD", &value);
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            7 => {
                let arguments = [ArgvItem::plain(OsStr::new("--password=transaction-secret"))];
                let variables = [(OsStr::new("PASSWORD"), OsStr::new("transaction-secret"))];
                let handle = batch.redact_process(OsStr::new("client"), arguments, variables);
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            8 => {
                let content_type = HeaderValue::from_static("application/json");
                let handle = batch.redact_http_body(
                    BodyCapture::complete(br#"{"password":"transaction-secret"}"#),
                    Some(&content_type),
                );
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(handle).is_ok());
            }
            _ => {
                let first = batch.redact_field("password", &value);
                let output = batch.finish();
                check_output(&output, output_limit);
                assert!(output.resolve(first).is_ok());
                let next = Redactor::standard().batch().finish();
                assert!(next.resolve(first).is_err());
            }
        }
    }
});

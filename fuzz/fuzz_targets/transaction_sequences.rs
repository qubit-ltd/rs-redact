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
use qubit_redact::RedactionBatchHandle;
use qubit_redact::RedactionBatchOutput;
use qubit_redact::RedactionCompletion;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;
use qubit_redact::formats::http::BodyCapture;

const FUZZ_SECRET: &str = "transaction-secret";

/// Ranks completion states from fully rendered to terminally exhausted.
#[must_use]
const fn completion_rank(completion: RedactionCompletion) -> u8 {
    match completion {
        RedactionCompletion::Complete => 0,
        RedactionCompletion::Truncated => 1,
        RedactionCompletion::Exhausted => 2,
    }
}

/// Checks invariants shared by every item published from one completed batch.
fn check_output(output: &RedactionBatchOutput, handles: &[RedactionBatchHandle], output_limit: usize) {
    assert!(output.summary().usage().output_bytes() <= output_limit);
    let mut item_output_bytes = 0;
    for handle in handles {
        let item = output
            .resolve(*handle)
            .expect("a handle must resolve from its owning batch");
        let text = item.text().as_str();
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
        assert!(!text.contains(FUZZ_SECRET));
        item_output_bytes += text.len();
        assert!(completion_rank(output.summary().completion()) >= completion_rank(item.summary().completion()));
    }
    assert_eq!(output.summary().usage().output_bytes(), item_output_bytes);
}

// Exercises multiple heterogeneous operations inside one transaction. Each
// handle remains unpublished until the shared batch has consumed every item.
fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(4096)];
    let redactor = Redactor::standard();
    let output_limit = redactor.policy().limits().max_output_bytes();
    let mut batch = redactor.batch();
    let mut handles = Vec::with_capacity(data.len().div_ceil(8).min(128));

    for chunk in data.chunks(8).take(128) {
        let selector = chunk.first().copied().unwrap_or_default();
        let value = String::from_utf8_lossy(chunk);
        let handle = match selector % 10 {
            0 => batch.redact_field("name", &value),
            1 => batch.redact_field("password", &value),
            2 => {
                let json = format!(r#"{{"password":"{FUZZ_SECRET}","noise":{selector}}}"#);
                batch.redact_json(&json)
            }
            3 => batch.redact_http_url("https://fuzz.example/?password=transaction-secret"),
            4 => batch.redact_uri("https://fuzz.example/?password=transaction-secret"),
            5 => {
                let items = [ArgvItem::sensitive(
                    OsStr::new("--password=transaction-secret"),
                    Sensitivity::Secret,
                )];
                batch.redact_argv(items)
            }
            6 => batch.redact_env("PASSWORD", &value),
            7 => {
                let arguments = [ArgvItem::sensitive(
                    OsStr::new("--password=transaction-secret"),
                    Sensitivity::Secret,
                )];
                let variables = [(OsStr::new("PASSWORD"), OsStr::new("transaction-secret"))];
                batch.redact_process(OsStr::new("client"), arguments, variables)
            }
            8 => {
                let content_type = HeaderValue::from_static("application/json");
                batch.redact_http_body(
                    BodyCapture::complete(br#"{"password":"transaction-secret"}"#),
                    Some(&content_type),
                )
            }
            _ => batch.redact_field("password", FUZZ_SECRET),
        };
        handles.push(handle);
    }

    let output = batch.finish();
    check_output(&output, &handles, output_limit);
});

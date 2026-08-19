// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public-API helpers shared by HTTP integration tests.

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

pub(crate) fn redact_body(redactor: &Redactor, capture: BodyCapture<'_>, content_type: Option<&HeaderValue>) -> String {
    redactor
        .redact_http_body(capture, content_type)
        .text()
        .as_str()
        .to_owned()
}

pub(crate) fn redact_url(redactor: &Redactor, value: &str) -> String {
    redactor.redact_http_url(value).text().as_str().to_owned()
}

pub(crate) fn redact_headers(policy: RedactionPolicy, headers: &HeaderMap) -> String {
    let mut session = Redactor::new(policy).session();
    session.http(|http| {
        http.headers(headers);
    });
    session.finish().text().as_str().to_owned()
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use qubit_sanitize::{
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
};

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
});

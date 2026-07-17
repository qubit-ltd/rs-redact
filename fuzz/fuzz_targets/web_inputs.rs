// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use libfuzzer_sys::fuzz_target;
use qubit_sanitize::{
    FormUrlEncodedSanitizer,
    NameMatchMode,
    UrlSanitizer,
};

fuzz_target!(|data: &[u8]| {
    let form_sanitizer = FormUrlEncodedSanitizer::default();
    let first_form =
        form_sanitizer.sanitize_bytes(data, NameMatchMode::ExactOrSuffix);
    let second_form =
        form_sanitizer.sanitize_bytes(data, NameMatchMode::ExactOrSuffix);
    assert_eq!(first_form, second_form);

    if let Ok(text) = std::str::from_utf8(data) {
        let url = format!("https://example.test/?{text}");
        let url_sanitizer = UrlSanitizer::default();
        let first_url =
            url_sanitizer.sanitize_url_str(&url, NameMatchMode::ExactOrSuffix);
        let second_url =
            url_sanitizer.sanitize_url_str(&url, NameMatchMode::ExactOrSuffix);
        assert_eq!(first_url, second_url);
    }
});

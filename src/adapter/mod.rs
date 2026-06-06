// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Adapters for sanitizing structured objects with core masking policies.

mod argv_sanitizer;
mod env_sanitizer;
mod form_url_encoded_sanitizer;
mod http;
mod url_sanitizer;

pub use argv_sanitizer::ArgvSanitizer;
pub use env_sanitizer::EnvSanitizer;
pub use form_url_encoded_sanitizer::FormUrlEncodedSanitizer;
pub use http::{
    HttpBodySanitizer,
    HttpHeaderSanitizer,
};
pub use url_sanitizer::UrlSanitizer;

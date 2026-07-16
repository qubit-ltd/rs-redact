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
#[cfg(any(feature = "web", feature = "http"))]
pub(crate) mod form_url_encoded;
#[cfg(feature = "web")]
mod form_url_encoded_sanitizer;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "web")]
mod url_sanitizer;

pub use argv_sanitizer::ArgvSanitizer;
pub use env_sanitizer::EnvSanitizer;
#[cfg(feature = "web")]
pub use form_url_encoded_sanitizer::FormUrlEncodedSanitizer;
#[cfg(feature = "http")]
pub use http::{
    BodyRedactionReason, BodySanitization, BodySanitizationStatus, HttpBodySanitizer,
    HttpHeaderSanitizer, TextBodyPolicy,
};
#[cfg(feature = "web")]
pub use url_sanitizer::UrlSanitizer;

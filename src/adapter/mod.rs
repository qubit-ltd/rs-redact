// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Adapters for sanitizing structured objects with core masking policies.

mod argv_sanitizer;
mod env_sanitizer;
#[cfg(any(feature = "form", feature = "http"))]
pub(crate) mod form_url_encoded;
#[cfg(any(feature = "form", feature = "http"))]
mod form_url_encoded_sanitizer;
#[cfg(feature = "http")]
mod http;
#[cfg(any(feature = "web", feature = "http"))]
mod url_path_policy;
#[cfg(any(feature = "web", feature = "http"))]
mod url_sanitizer;

pub use argv_sanitizer::ArgvSanitizer;
pub use env_sanitizer::EnvSanitizer;
#[cfg(any(feature = "form", feature = "http"))]
pub use form_url_encoded_sanitizer::FormUrlEncodedSanitizer;
#[cfg(feature = "http")]
pub use http::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    HttpHeaderSanitizer,
    TextBodyPolicy,
    UnkeyedJsonValuePolicy,
};
#[cfg(any(feature = "web", feature = "http"))]
pub use url_path_policy::UrlPathPolicy;
#[cfg(any(feature = "web", feature = "http"))]
pub use url_sanitizer::UrlSanitizer;

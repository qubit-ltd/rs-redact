// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for crate-level exports.

use qubit_sanitize::{
    ArgvSanitizer,
    DEFAULT_EXTRA_FIELDS,
    EnvSanitizer,
    FieldSanitizePolicy,
    FieldSanitizer,
    MaskPolicies,
    MaskPolicy,
    NameMatchMode,
    RedactedDebug,
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
    redacted_debug,
};
#[cfg(feature = "http")]
use qubit_sanitize::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
    HttpBodySanitizer,
    HttpHeaderSanitizer,
    TextBodyPolicy,
};
#[cfg(feature = "web")]
use qubit_sanitize::{
    FormUrlEncodedSanitizer,
    UrlSanitizer,
};

#[test]
fn test_lib_exports_public_api() {
    let _ = DEFAULT_EXTRA_FIELDS;
    let _ = ArgvSanitizer::default();
    let _ = EnvSanitizer::default();
    let _ = FieldSanitizePolicy::default();
    let _ = FieldSanitizer::default();
    let _ = MaskPolicies::default();
    let _ = MaskPolicy::fixed("****");
    let _ = NameMatchMode::Exact;
    let _: RedactedDebug<'_, str> = redacted_debug("secret");
    let _ = SensitiveFieldPreset::Credentials;
    let _ = SensitiveFields::default();
    let _ = SensitivityLevel::High;
    #[cfg(feature = "web")]
    {
        let _ = FormUrlEncodedSanitizer::default();
        let _ = UrlSanitizer::default();
    }
    #[cfg(feature = "http")]
    {
        let _: Option<BodySanitization> = None;
        let _ =
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidJson);
        let _ = HttpBodySanitizer::default();
        let _ = HttpHeaderSanitizer::default();
        let _ = TextBodyPolicy::default();
    }
}

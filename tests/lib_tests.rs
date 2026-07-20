// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for crate-level exports.

#[cfg(feature = "form")]
use qubit_redact::FormUrlEncodedSanitizer;
#[cfg(feature = "web")]
use qubit_redact::UrlSanitizer;
use qubit_redact::{
    ArgvSanitizer,
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
    escape_log_control_characters,
    redacted_debug,
};
#[cfg(feature = "http")]
use qubit_redact::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    HttpHeaderSanitizer,
    TextBodyPolicy,
    UnkeyedJsonValuePolicy,
};

#[test]
fn test_lib_exports_public_api() {
    let _ = ArgvSanitizer::default();
    let _ = EnvSanitizer::default();
    let _ = escape_log_control_characters("safe");
    let _ = FieldSanitizePolicy::default();
    let _ = FieldSanitizer::default();
    let _ = MaskPolicies::default();
    let _ = MaskPolicy::fixed("****");
    let _ = NameMatchMode::Exact;
    let _: RedactedDebug<'_, str> = redacted_debug("secret");
    let _ = SensitiveFieldPreset::Credentials;
    let _ = SensitiveFields::default();
    let _ = SensitivityLevel::High;
    #[cfg(feature = "form")]
    let _ = FormUrlEncodedSanitizer::default();
    #[cfg(feature = "web")]
    let _ = UrlSanitizer::default();
    #[cfg(feature = "http")]
    {
        let _: Option<BodySanitization> = None;
        let _ = BodySourceLength::UnknownTruncated;
        let _ =
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidJson);
        let _ = HttpBodySanitizer::default();
        let _ = HttpHeaderSanitizer::default();
        let _ = TextBodyPolicy::default();
        let _ = UnkeyedJsonValuePolicy::default();
    }
}

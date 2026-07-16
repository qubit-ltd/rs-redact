// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared URL-encoded form sanitization helpers.

use form_urlencoded::Serializer;

use crate::{
    FieldSanitizer,
    NameMatchMode,
};

/// Sanitizes URL-encoded form bytes with a field sanitizer.
///
/// Field order and duplicate keys are preserved. The returned string is valid
/// URL-encoded form data.
///
/// # Parameters
///
/// * `field_sanitizer` - Core sanitizer used for form field values.
/// * `form` - URL-encoded form bytes.
/// * `match_mode` - Field-name matching mode for form keys.
///
/// # Returns
///
/// Sanitized URL-encoded form text.
#[must_use = "use the returned sanitized form instead of the original form"]
pub(crate) fn sanitize_form_urlencoded(
    field_sanitizer: &FieldSanitizer,
    form: &[u8],
    match_mode: NameMatchMode,
) -> String {
    let mut serializer = Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(form) {
        let sanitized_value = field_sanitizer.sanitize_value(
            key.as_ref(),
            value.as_ref(),
            match_mode,
        );
        serializer.append_pair(key.as_ref(), sanitized_value.as_ref());
    }
    serializer.finish()
}

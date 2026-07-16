// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use http::HeaderValue;
use serde_json::Value;

use crate::{
    FieldSanitizer,
    NameMatchMode,
    adapter::form_url_encoded::sanitize_form_urlencoded,
};

use super::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
    body_bytes::trim_ascii_whitespace,
    content_type,
    internal::BodyInputKind,
    multipart,
    redaction_markers::{
        INVALID_CONTENT_TYPE_REDACTED,
        MULTIPART_BODY_REDACTED,
        TEXT_BODY_REDACTED,
        UNSUPPORTED_BODY_REDACTED,
    },
    text_body_policy::TextBodyPolicy,
};

/// Sanitizes HTTP body bytes for logs and diagnostics.
///
/// Structured formats are sanitized by field name. Declared opaque `text/*`
/// bodies and non-sensitive multipart text parts use
/// [`TextBodyPolicy::Redact`] by default because they do not expose field names
/// that can be matched safely. Callers can explicitly select
/// [`TextBodyPolicy::PassThrough`] when they accept responsibility for the
/// original text's diagnostic and logging risks.
#[must_use = "the sanitizer must be used to produce sanitized HTTP bodies"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBodySanitizer {
    /// Core sanitizer used for body field values.
    field_sanitizer: FieldSanitizer,
    /// Rendering policy for opaque text bodies.
    text_body_policy: TextBodyPolicy,
}

impl HttpBodySanitizer {
    /// Creates an HTTP body sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for body field values.
    ///
    /// # Returns
    ///
    /// New HTTP body sanitizer.
    #[inline(always)]
    pub const fn new(field_sanitizer: FieldSanitizer) -> Self {
        Self {
            field_sanitizer,
            text_body_policy: TextBodyPolicy::Redact,
        }
    }

    /// Returns this sanitizer with a replacement opaque-text policy.
    ///
    /// # Parameters
    ///
    /// * `text_body_policy` - New policy for declared `text/*` bodies and
    ///   non-sensitive multipart text parts.
    ///
    /// # Returns
    ///
    /// The updated sanitizer.
    #[inline]
    pub const fn with_text_body_policy(
        mut self,
        text_body_policy: TextBodyPolicy,
    ) -> Self {
        self.text_body_policy = text_body_policy;
        self
    }

    /// Returns the underlying core field sanitizer.
    ///
    /// # Returns
    ///
    /// Borrowed core field sanitizer.
    #[inline(always)]
    pub const fn field_sanitizer(&self) -> &FieldSanitizer {
        &self.field_sanitizer
    }

    /// Returns the underlying core field sanitizer mutably.
    ///
    /// # Returns
    ///
    /// Mutable core field sanitizer.
    #[inline(always)]
    pub fn field_sanitizer_mut(&mut self) -> &mut FieldSanitizer {
        &mut self.field_sanitizer
    }

    /// Returns the policy used for opaque HTTP text bodies.
    ///
    /// # Returns
    ///
    /// The current text body policy. The default is
    /// [`TextBodyPolicy::Redact`].
    #[inline(always)]
    pub const fn text_body_policy(&self) -> TextBodyPolicy {
        self.text_body_policy
    }

    /// Replaces the policy used for opaque HTTP text bodies.
    ///
    /// # Parameters
    ///
    /// * `text_body_policy` - New policy for declared `text/*` bodies and
    ///   non-sensitive multipart text parts.
    #[inline(always)]
    pub fn set_text_body_policy(&mut self, text_body_policy: TextBodyPolicy) {
        self.text_body_policy = text_body_policy;
    }

    /// Sanitizes a complete HTTP body.
    ///
    /// Use this method when `body` contains the complete source bytes. The
    /// sanitizer may parse structured media types such as JSON, NDJSON,
    /// URL-encoded forms, and multipart bodies because it can inspect the whole
    /// payload. It does not append any truncation marker.
    ///
    /// Use [`Self::sanitize_body_preview`] instead when the caller only has a
    /// bounded prefix of a larger body. Preview sanitization is more
    /// conservative for structured formats that cannot be parsed safely from a
    /// truncated prefix.
    ///
    /// The returned result contains diagnostic content and source-length
    /// metadata. Its rendered form is not a replayable HTTP body. Structured
    /// outputs may be compacted and may not preserve the original field order,
    /// whitespace, or JSON value types for redacted fields.
    ///
    /// # Parameters
    ///
    /// * `body` - Complete HTTP body bytes.
    /// * `content_type` - Optional `Content-Type` header used to select
    ///   structured parsing rules.
    /// * `match_mode` - Field-name matching mode for structured body fields.
    ///
    /// # Returns
    ///
    /// Structured body sanitization result. Declared `text/*` bodies are
    /// redacted unless callers explicitly select
    /// [`TextBodyPolicy::PassThrough`]. Unsupported UTF-8 bodies are redacted.
    /// Binary bodies are represented by a byte-count marker. Bodies with a
    /// present but non-UTF-8 `Content-Type` are fully redacted because the
    /// structured parser cannot choose a safe media-type rule.
    #[inline(always)]
    pub fn sanitize_body(
        &self,
        body: &[u8],
        content_type: Option<&HeaderValue>,
        match_mode: NameMatchMode,
    ) -> BodySanitization {
        self.sanitize_body_inner(
            body,
            body.len(),
            content_type,
            BodyInputKind::Complete,
            match_mode,
        )
    }

    /// Sanitizes a caller-provided HTTP body preview.
    ///
    /// Use this method when `body_prefix` is already limited by the caller, for
    /// example before logging a large body. `source_len` is the total body
    /// length when known; values smaller than `body_prefix.len()` are treated
    /// as `body_prefix.len()`. When the source length is greater than the
    /// prefix length, the rendered output includes a truncation marker.
    ///
    /// Unlike [`Self::sanitize_body`], this method must assume the bytes may be
    /// incomplete. JSON, NDJSON, and multipart previews are redacted when they
    /// cannot be parsed safely, which avoids leaking partial sensitive values.
    /// URL-encoded forms and declared `text/*` bodies render the available
    /// prefix with a truncation marker when needed.
    ///
    /// The returned result contains diagnostic content and source-length
    /// metadata. Its rendered form is not a replayable HTTP body. Structured
    /// outputs may be compacted and may not preserve the original field order,
    /// whitespace, or JSON value types for redacted fields.
    ///
    /// # Parameters
    ///
    /// * `body_prefix` - Body bytes available for preview rendering.
    /// * `source_len` - Total source body length when known.
    /// * `content_type` - Optional `Content-Type` header used to select
    ///   structured parsing rules.
    /// * `match_mode` - Field-name matching mode for structured body fields.
    ///
    /// # Returns
    ///
    /// Structured preview sanitization result. Rendering it adds a truncation
    /// marker when `source_len` exceeds `body_prefix.len()`. Declared `text/*`
    /// previews are redacted unless callers explicitly select
    /// [`TextBodyPolicy::PassThrough`]. Unsupported UTF-8 previews are
    /// redacted. Bodies with a present but non-UTF-8 `Content-Type` are fully
    /// redacted because the structured parser cannot choose a safe media-type
    /// rule.
    #[inline(always)]
    pub fn sanitize_body_preview(
        &self,
        body_prefix: &[u8],
        source_len: usize,
        content_type: Option<&HeaderValue>,
        match_mode: NameMatchMode,
    ) -> BodySanitization {
        self.sanitize_body_inner(
            body_prefix,
            source_len.max(body_prefix.len()),
            content_type,
            BodyInputKind::Preview,
            match_mode,
        )
    }

    /// Sanitizes one JSON document.
    ///
    /// # Parameters
    ///
    /// * `bytes` - UTF-8 JSON bytes.
    /// * `match_mode` - Field-name matching mode for JSON object keys.
    ///
    /// # Returns
    ///
    /// Sanitized compact JSON text, or `None` when parsing or rendering fails.
    pub(super) fn sanitize_json(
        &self,
        bytes: &[u8],
        match_mode: NameMatchMode,
    ) -> Option<String> {
        let mut value = serde_json::from_slice::<Value>(bytes).ok()?;
        self.redact_json_value(&mut value, match_mode);
        serde_json::to_string(&value).ok()
    }

    /// Sanitizes newline-delimited JSON.
    ///
    /// # Parameters
    ///
    /// * `bytes` - UTF-8 NDJSON bytes.
    /// * `match_mode` - Field-name matching mode for JSON object keys.
    ///
    /// # Returns
    ///
    /// Sanitized NDJSON text, or `None` when any non-empty line is invalid.
    pub(super) fn sanitize_ndjson(
        &self,
        bytes: &[u8],
        match_mode: NameMatchMode,
    ) -> Option<String> {
        let text = std::str::from_utf8(bytes).ok()?;
        let trailing_newline = text.ends_with('\n');
        let mut sanitized_lines = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                sanitized_lines.push(String::new());
                continue;
            }
            let mut value = serde_json::from_str::<Value>(line).ok()?;
            self.redact_json_value(&mut value, match_mode);
            sanitized_lines.push(serde_json::to_string(&value).ok()?);
        }
        let mut result = sanitized_lines.join("\n");
        if trailing_newline {
            result.push('\n');
        }
        Some(result)
    }

    /// Sanitizes URL-encoded form body bytes.
    ///
    /// # Parameters
    ///
    /// * `bytes` - URL-encoded form body bytes.
    /// * `match_mode` - Field-name matching mode for form keys.
    ///
    /// # Returns
    ///
    /// Sanitized URL-encoded form text.
    #[must_use = "use the returned sanitized form instead of the original body"]
    #[inline(always)]
    pub(super) fn sanitize_form(
        &self,
        bytes: &[u8],
        match_mode: NameMatchMode,
    ) -> String {
        sanitize_form_urlencoded(&self.field_sanitizer, bytes, match_mode)
    }

    /// Sanitizes complete or preview body bytes.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Body bytes to render.
    /// * `source_len` - Full source length used for preview and binary markers.
    /// * `content_type` - Optional `Content-Type` header.
    /// * `input_kind` - Whether `bytes` are complete or a preview prefix.
    /// * `match_mode` - Field-name matching mode for structured body fields.
    ///
    /// # Returns
    ///
    /// Structured sanitized body result for diagnostic output.
    fn sanitize_body_inner(
        &self,
        bytes: &[u8],
        source_len: usize,
        content_type: Option<&HeaderValue>,
        input_kind: BodyInputKind,
        match_mode: NameMatchMode,
    ) -> BodySanitization {
        let result = |content, status| {
            BodySanitization::new(content, status, bytes.len(), source_len)
        };
        if bytes.is_empty() {
            return result(
                input_kind.empty_content(),
                BodySanitizationStatus::Empty,
            );
        }

        let content_type = match content_type::content_type_to_str(content_type)
        {
            Some(Ok(content_type)) => Some(content_type),
            Some(Err(_)) => {
                return result(
                    INVALID_CONTENT_TYPE_REDACTED.to_string(),
                    BodySanitizationStatus::Redacted(
                        BodyRedactionReason::InvalidContentType,
                    ),
                );
            }
            None => None,
        };

        if let Some(content_type) =
            content_type.filter(|value| content_type::is_multipart(value))
        {
            return self.sanitize_multipart_body(
                bytes,
                source_len,
                content_type,
                input_kind,
                match_mode,
            );
        }
        if content_type.is_some_and(content_type::is_ndjson) {
            return self.sanitize_ndjson_body(
                bytes, source_len, input_kind, match_mode,
            );
        }
        if self.is_json_body(content_type, bytes) {
            return self
                .sanitize_json_body(bytes, source_len, input_kind, match_mode);
        }
        if content_type.is_some_and(content_type::is_form_urlencoded) {
            return self.sanitize_form_body(bytes, source_len, match_mode);
        }

        self.sanitize_fallback_body(bytes, source_len, content_type)
    }

    /// Sanitizes a body declared as multipart.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Complete body bytes or the captured preview prefix.
    /// * `source_len` - Full source length used for result metadata.
    /// * `content_type` - Declared multipart content type.
    /// * `input_kind` - Whether `bytes` are complete or a preview prefix.
    /// * `match_mode` - Field-name matching mode for multipart fields.
    ///
    /// # Returns
    ///
    /// A sanitized multipart result, or a redacted result when the preview is
    /// truncated or the multipart body is invalid.
    fn sanitize_multipart_body(
        &self,
        bytes: &[u8],
        source_len: usize,
        content_type: &str,
        input_kind: BodyInputKind,
        match_mode: NameMatchMode,
    ) -> BodySanitization {
        let result = |content, status| {
            BodySanitization::new(content, status, bytes.len(), source_len)
        };
        if input_kind.is_truncated(bytes.len(), source_len) {
            return result(
                MULTIPART_BODY_REDACTED.to_string(),
                BodySanitizationStatus::Redacted(
                    BodyRedactionReason::TruncatedMultipart,
                ),
            );
        }
        if let Some(multipart) = multipart::sanitize_multipart(
            self,
            Some(content_type),
            bytes,
            match_mode,
        ) {
            let status = if multipart.contains_passed_through_text() {
                BodySanitizationStatus::PassedThrough
            } else {
                BodySanitizationStatus::Sanitized
            };
            return result(multipart.into_content(), status);
        }
        result(
            MULTIPART_BODY_REDACTED.to_string(),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::InvalidMultipart,
            ),
        )
    }

    /// Sanitizes a body declared as newline-delimited JSON.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Complete body bytes or the captured preview prefix.
    /// * `source_len` - Full source length used for result metadata.
    /// * `input_kind` - Whether `bytes` are complete or a preview prefix.
    /// * `match_mode` - Field-name matching mode for JSON object keys.
    ///
    /// # Returns
    ///
    /// A sanitized NDJSON result, or a redacted result with the marker and
    /// reason appropriate for complete or preview input when parsing fails.
    fn sanitize_ndjson_body(
        &self,
        bytes: &[u8],
        source_len: usize,
        input_kind: BodyInputKind,
        match_mode: NameMatchMode,
    ) -> BodySanitization {
        if let Some(text) = self.sanitize_ndjson(bytes, match_mode) {
            return BodySanitization::new(
                text,
                BodySanitizationStatus::Sanitized,
                bytes.len(),
                source_len,
            );
        }
        BodySanitization::new(
            input_kind.invalid_ndjson_marker().to_string(),
            BodySanitizationStatus::Redacted(
                input_kind.invalid_ndjson_reason(),
            ),
            bytes.len(),
            source_len,
        )
    }

    /// Sanitizes a body selected as JSON by declaration or sniffing.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Complete body bytes or the captured preview prefix.
    /// * `source_len` - Full source length used for result metadata.
    /// * `input_kind` - Whether `bytes` are complete or a preview prefix.
    /// * `match_mode` - Field-name matching mode for JSON object keys.
    ///
    /// # Returns
    ///
    /// A sanitized JSON result, or a redacted result with the marker and
    /// reason appropriate for complete or preview input when parsing fails.
    fn sanitize_json_body(
        &self,
        bytes: &[u8],
        source_len: usize,
        input_kind: BodyInputKind,
        match_mode: NameMatchMode,
    ) -> BodySanitization {
        if let Some(text) = self.sanitize_json(bytes, match_mode) {
            return BodySanitization::new(
                text,
                BodySanitizationStatus::Sanitized,
                bytes.len(),
                source_len,
            );
        }
        BodySanitization::new(
            input_kind.invalid_json_marker().to_string(),
            BodySanitizationStatus::Redacted(input_kind.invalid_json_reason()),
            bytes.len(),
            source_len,
        )
    }

    /// Sanitizes a body declared as URL-encoded form data.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Complete body bytes or the captured preview prefix.
    /// * `source_len` - Full source length used for result metadata.
    /// * `match_mode` - Field-name matching mode for form keys.
    ///
    /// # Returns
    ///
    /// A sanitized URL-encoded form result containing the captured and source
    /// lengths.
    #[inline(always)]
    fn sanitize_form_body(
        &self,
        bytes: &[u8],
        source_len: usize,
        match_mode: NameMatchMode,
    ) -> BodySanitization {
        BodySanitization::new(
            self.sanitize_form(bytes, match_mode),
            BodySanitizationStatus::Sanitized,
            bytes.len(),
            source_len,
        )
    }

    /// Sanitizes a body not handled by a structured media-type branch.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Complete body bytes or the captured preview prefix.
    /// * `source_len` - Full source length used for result metadata and binary
    ///   byte-count markers.
    /// * `content_type` - Optional declared content type used to recognize
    ///   opaque text bodies.
    ///
    /// # Returns
    ///
    /// A policy-controlled text result for declared UTF-8 text, an unsupported
    /// media-type redaction for other UTF-8 bodies, or a binary byte-count
    /// result for non-UTF-8 bodies.
    fn sanitize_fallback_body(
        &self,
        bytes: &[u8],
        source_len: usize,
        content_type: Option<&str>,
    ) -> BodySanitization {
        let result = |content, status| {
            BodySanitization::new(content, status, bytes.len(), source_len)
        };
        match std::str::from_utf8(bytes) {
            Ok(text) if content_type.is_some_and(content_type::is_text) => {
                let status = match self.text_body_policy {
                    TextBodyPolicy::Redact => BodySanitizationStatus::Redacted(
                        BodyRedactionReason::OpaqueText,
                    ),
                    TextBodyPolicy::PassThrough => {
                        BodySanitizationStatus::PassedThrough
                    }
                };
                result(self.sanitize_text_body(text), status)
            }
            Ok(_) => result(
                UNSUPPORTED_BODY_REDACTED.to_string(),
                BodySanitizationStatus::Redacted(
                    BodyRedactionReason::UnsupportedMediaType,
                ),
            ),
            Err(_) => result(
                format!("<binary {} bytes>", source_len.max(bytes.len())),
                BodySanitizationStatus::Binary,
            ),
        }
    }

    /// Sanitizes an opaque top-level text body according to the text policy.
    ///
    /// # Parameters
    ///
    /// * `text` - UTF-8 text body whose content has no structured field names.
    ///
    /// # Returns
    ///
    /// A redaction marker by default, or `text` unchanged when callers choose
    /// [`TextBodyPolicy::PassThrough`].
    #[must_use = "use the returned policy-controlled text instead of the original body"]
    #[inline]
    fn sanitize_text_body(&self, text: &str) -> String {
        match self.text_body_policy {
            TextBodyPolicy::Redact => TEXT_BODY_REDACTED.to_string(),
            TextBodyPolicy::PassThrough => text.to_string(),
        }
    }

    /// Returns whether body bytes should be treated as JSON.
    ///
    /// # Parameters
    ///
    /// * `content_type` - Optional content type text.
    /// * `bytes` - Body bytes to inspect when no content type is present.
    ///
    /// # Returns
    ///
    /// `true` when the content type declares JSON or the bytes look like JSON.
    #[must_use]
    #[inline]
    fn is_json_body(&self, content_type: Option<&str>, bytes: &[u8]) -> bool {
        if let Some(content_type) = content_type {
            return content_type::is_json(content_type);
        }
        let trimmed = trim_ascii_whitespace(bytes);
        matches!(trimmed.first(), Some(b'{') | Some(b'['))
    }

    /// Redacts sensitive object fields in a JSON value.
    ///
    /// # Parameters
    ///
    /// * `value` - JSON value to mutate.
    /// * `match_mode` - Field-name matching mode for JSON object keys.
    fn redact_json_value(&self, value: &mut Value, match_mode: NameMatchMode) {
        match value {
            Value::Object(map) => {
                for (key, value) in map.iter_mut() {
                    if let Some(masked) =
                        self.mask_json_field_value(key, value, match_mode)
                    {
                        *value = Value::String(masked);
                    } else {
                        self.redact_json_value(value, match_mode);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_json_value(item, match_mode);
                }
            }
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_) => {}
        }
    }

    /// Masks a sensitive JSON field value.
    ///
    /// # Parameters
    ///
    /// * `field` - JSON object key used for sensitivity lookup.
    /// * `value` - JSON value to mask when the key is sensitive.
    /// * `match_mode` - Field-name matching mode for `field`.
    ///
    /// # Returns
    ///
    /// `Some(masked)` when `field` is sensitive, otherwise `None`.
    fn mask_json_field_value(
        &self,
        field: &str,
        value: &Value,
        match_mode: NameMatchMode,
    ) -> Option<String> {
        let level = self
            .field_sanitizer
            .sensitivity_for_name(field, match_mode)?;
        let serialized;
        let value = match value {
            Value::String(value) => value.as_str(),
            _ => {
                serialized = value.to_string();
                serialized.as_str()
            }
        };
        Some(
            self.field_sanitizer
                .policy()
                .mask_policies()
                .for_level(level)
                .mask(value)
                .into_owned(),
        )
    }
}

impl Default for HttpBodySanitizer {
    /// Creates an HTTP body sanitizer using [`FieldSanitizer::default`].
    ///
    /// # Returns
    ///
    /// An HTTP body sanitizer with default sensitive fields and opaque-text
    /// redaction.
    #[inline(always)]
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}

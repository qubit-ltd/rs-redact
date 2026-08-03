// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Policy-driven URI redaction facade.

use std::{
    borrow::Cow,
    fmt,
};

use fluent_uri::Uri;

use crate::{
    GlobalRedactionConfig,
    RedactedText,
    Redactor,
    Sensitivity,
};

use super::{
    UriComponent,
    UriFragmentPolicy,
    UriPathPolicy,
    UriRedaction,
    UriRedactionPolicy,
    UriRedactionReason,
    UriRedactionStatus,
};

const INVALID_URI: &str = "<invalid URI>";
const TRUNCATED: &str = "<truncated>";

/// Redacts URI strings using one immutable policy snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriRedactor {
    policy: UriRedactionPolicy,
}

impl UriRedactor {
    /// Creates a URI redactor from an explicit immutable policy.
    #[inline]
    pub const fn new(policy: UriRedactionPolicy) -> Self {
        Self { policy }
    }

    /// Returns the immutable URI policy snapshot.
    #[must_use = "use the URI policy snapshot"]
    #[inline]
    pub const fn policy(&self) -> &UriRedactionPolicy {
        &self.policy
    }

    /// Redacts one absolute URI and returns safe text plus metadata.
    ///
    /// Parsing is strict. Invalid syntax, invalid UTF-8 in a percent-encoded
    /// field, and budget violations all return a fixed marker without any
    /// portion of the input URI.
    #[must_use = "use the structured URI redaction result"]
    pub fn redact_uri_str(&self, input: &str) -> UriRedaction {
        if input.len()
            > self
                .policy
                .redaction_policy()
                .diagnostic_budget()
                .max_input_bytes()
        {
            return invalid_result(UriRedactionReason::InputLimitExceeded);
        }

        let parsed = match Uri::<&str>::parse(input) {
            Ok(parsed) => parsed,
            Err(_) => return invalid_result(UriRedactionReason::InvalidUri),
        };
        let mut reasons = Vec::new();
        let mut components = Vec::new();
        let mut rendered = String::with_capacity(input.len());
        let scheme = parsed.scheme().as_str();
        let scheme_end = scheme.len() + 1;
        rendered.push_str(&input[..scheme_end]);
        let mut cursor = scheme_end;

        if let Some(authority) = parsed.authority() {
            rendered.push_str("//");
            cursor += 2;
            match redact_authority(
                authority.as_str(),
                &self.policy,
                &mut reasons,
                &mut components,
            ) {
                Ok(authority) => rendered.push_str(&authority),
                Err(_) => {
                    return invalid_result(UriRedactionReason::InvalidUri);
                }
            }
            cursor += authority.as_str().len();
        }

        let path = parsed.path().as_str();
        if self.policy.path_policy() == UriPathPolicy::Redact
            && !path.is_empty()
            && path != "/"
        {
            mark_component(UriComponent::Path, &mut reasons, &mut components);
            if path.starts_with('/') {
                rendered.push_str("/%3Credacted%3E");
            } else {
                rendered.push_str("%3Credacted%3E");
            }
        } else {
            rendered.push_str(path);
        }
        cursor += path.len();

        if let Some(query) = parsed.query() {
            rendered.push('?');
            cursor += 1;
            match redact_query(
                query.as_str(),
                &self.policy,
                &mut reasons,
                &mut components,
            ) {
                Ok(query) => rendered.push_str(&query),
                Err(reason) => return invalid_result(reason),
            }
            cursor += query.as_str().len();
        }

        if let Some(fragment) = parsed.fragment() {
            rendered.push('#');
            cursor += 1;
            if self.policy.fragment_policy() == UriFragmentPolicy::Redact
                && !fragment.as_str().is_empty()
            {
                mark_component(
                    UriComponent::Fragment,
                    &mut reasons,
                    &mut components,
                );
                rendered.push_str(&encode_uri_component(
                    self.policy
                        .redaction_policy()
                        .masking()
                        .mask_opaque(Sensitivity::High),
                ));
            } else {
                rendered.push_str(fragment.as_str());
            }
            cursor += fragment.as_str().len();
        }
        debug_assert_eq!(cursor, input.len());

        let status = if components.is_empty() {
            UriRedactionStatus::PassedThrough
        } else {
            UriRedactionStatus::Redacted
        };
        finish_result(
            rendered,
            status,
            reasons,
            components,
            self.policy
                .redaction_policy()
                .diagnostic_budget()
                .max_output_bytes(),
        )
    }
}

impl Default for UriRedactor {
    /// Creates a redactor from the process-wide URI policy snapshot.
    #[inline]
    fn default() -> Self {
        Self::new(GlobalRedactionConfig::current().uri_policy().clone())
    }
}

/// Redacts userinfo while preserving the authority's raw host and port.
fn redact_authority(
    authority: &str,
    policy: &UriRedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) -> Result<String, ()> {
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return Ok(authority.to_owned());
    };
    let Some((username, password)) = userinfo.split_once(':') else {
        return redact_userinfo_part(
            userinfo, "username", host, policy, reasons, components,
        );
    };
    let username = redact_userinfo_value(
        username,
        "username",
        UriComponent::Username,
        policy,
        reasons,
        components,
    )?;
    let password = redact_userinfo_value(
        password,
        "password",
        UriComponent::Password,
        policy,
        reasons,
        components,
    )?;
    Ok(format!("{username}:{password}@{host}"))
}

/// Redacts a userinfo value that has no password delimiter.
fn redact_userinfo_part(
    username: &str,
    field: &str,
    host: &str,
    policy: &UriRedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) -> Result<String, ()> {
    let username = redact_userinfo_value(
        username,
        field,
        UriComponent::Username,
        policy,
        reasons,
        components,
    )?;
    Ok(format!("{username}@{host}"))
}

/// Applies a named field policy to one raw userinfo component.
fn redact_userinfo_value(
    raw: &str,
    field: &str,
    component: UriComponent,
    policy: &UriRedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) -> Result<String, ()> {
    let decoded = decode_uri_component(raw).map_err(|_| ())?;
    let redactor = Redactor::new(policy.redaction_policy().clone());
    let result = redactor.redact_field(field, &decoded);
    if result.is_masked() {
        mark_component(component, reasons, components);
        Ok(encode_uri_component(result.as_str()))
    } else {
        Ok(raw.to_owned())
    }
}

/// Redacts query values after strict percent decoding.
fn redact_query(
    query: &str,
    policy: &UriRedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) -> Result<String, UriRedactionReason> {
    let redactor = Redactor::new(policy.redaction_policy().clone());
    let mut output = String::with_capacity(query.len());
    for (index, pair) in query.split('&').enumerate() {
        if index != 0 {
            output.push('&');
        }
        let Some((raw_key, raw_value)) = pair.split_once('=') else {
            decode_uri_component(pair)
                .map_err(|_| UriRedactionReason::UndecodableQueryKey)?;
            output.push_str(pair);
            continue;
        };
        let key = decode_uri_component(raw_key)
            .map_err(|_| UriRedactionReason::UndecodableQueryKey)?;
        let value = decode_uri_component(raw_value)
            .map_err(|_| UriRedactionReason::UndecodableQueryValue)?;
        let result = redactor.redact_field(&key, &value);
        if result.is_masked() {
            mark_component(UriComponent::Query, reasons, components);
            output.push_str(raw_key);
            output.push('=');
            output.push_str(&encode_uri_component(result.as_str()));
        } else {
            output.push_str(pair);
        }
    }
    Ok(output)
}

/// Decodes percent escapes without applying form-urlencoded `+` semantics.
fn decode_uri_component(raw: &str) -> Result<String, ()> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(());
            }
            let high = hex_value(bytes[index + 1]).ok_or(())?;
            let low = hex_value(bytes[index + 2]).ok_or(())?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

/// Percent-encodes a replacement while retaining URI-safe delimiters.
fn encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
            )
        {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

/// Converts one hexadecimal ASCII byte to its numeric value.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Converts a nibble to an uppercase hexadecimal digit.
const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'A' + value - 10) as char,
    }
}

/// Records a sensitive component and its corresponding reason once.
fn mark_component(
    component: UriComponent,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) {
    if !components.contains(&component) {
        components.push(component);
    }
    let reason = UriRedactionReason::SensitiveComponent(component);
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// Builds a fixed-marker result for malformed or over-budget input.
fn invalid_result(reason: UriRedactionReason) -> UriRedaction {
    UriRedaction {
        text: safe_text(INVALID_URI.to_owned()),
        status: UriRedactionStatus::Invalid,
        reasons: vec![reason],
        components: Vec::new(),
        truncated: false,
    }
}

/// Escapes, bounds, and packages the rendered URI result.
fn finish_result(
    rendered: String,
    status: UriRedactionStatus,
    mut reasons: Vec<UriRedactionReason>,
    components: Vec<UriComponent>,
    max_output_bytes: usize,
) -> UriRedaction {
    let mut truncated = false;
    let mut safe = RedactedText::new(Cow::Owned(rendered))
        .escape_for_log()
        .into_owned();
    if safe.len() > max_output_bytes {
        truncated = true;
        let prefix_limit = max_output_bytes.saturating_sub(TRUNCATED.len());
        let mut boundary = prefix_limit.min(safe.len());
        while boundary > 0 && !safe.is_char_boundary(boundary) {
            boundary -= 1;
        }
        safe.truncate(boundary);
        safe.push_str(TRUNCATED);
        reasons.push(UriRedactionReason::OutputTruncated);
    }
    UriRedaction {
        text: safe_text(safe),
        status,
        reasons,
        components,
        truncated,
    }
}

/// Converts owned output into the library's log-safe text wrapper.
fn safe_text(value: String) -> crate::LogSafeText<'static> {
    RedactedText::new(Cow::Owned(value)).escape_for_log()
}

impl fmt::Display for UriRedactor {
    /// Formats the policy snapshot without exposing URI input.
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UriRedactor")
    }
}

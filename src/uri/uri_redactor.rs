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
    fmt::{
        self,
        Write,
    },
};

use fluent_uri::Uri;

use crate::{
    GlobalRedactionConfig,
    RedactedText,
    Sensitivity,
    policy::ResolvedField,
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

use super::internal::{
    BoundedUriWriter,
    UriComponentWriter,
};

const INVALID_URI: &str = "<invalid URI>";

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
        let mut rendered = BoundedUriWriter::new(
            self.policy
                .redaction_policy()
                .diagnostic_budget()
                .max_output_bytes(),
        );
        let scheme = parsed.scheme().as_str();
        let scheme_end = scheme.len() + 1;
        rendered.write_str(&input[..scheme_end]);

        if let Some(authority) = parsed.authority() {
            rendered.write_str("//");
            if redact_authority(
                authority.as_str(),
                &self.policy,
                &mut reasons,
                &mut components,
                &mut rendered,
            )
            .is_err()
            {
                return invalid_result(UriRedactionReason::InvalidUri);
            }
        }

        let path = parsed.path().as_str();
        if self.policy.path_policy() == UriPathPolicy::Redact
            && !path.is_empty()
            && path != "/"
        {
            mark_component(UriComponent::Path, &mut reasons, &mut components);
            if path.starts_with('/') {
                rendered.write_str("/%3Credacted%3E");
            } else {
                rendered.write_str("%3Credacted%3E");
            }
        } else {
            rendered.write_str(path);
        }

        if let Some(query) = parsed.query() {
            rendered.write_str("?");
            if let Err(reason) = redact_query(
                query.as_str(),
                &self.policy,
                &mut reasons,
                &mut components,
                &mut rendered,
            ) {
                return invalid_result(reason);
            }
        }

        if let Some(fragment) = parsed.fragment() {
            rendered.write_str("#");
            if self.policy.fragment_policy() == UriFragmentPolicy::Redact
                && !fragment.as_str().is_empty()
            {
                mark_component(
                    UriComponent::Fragment,
                    &mut reasons,
                    &mut components,
                );
                write_opaque_mask(
                    &self.policy,
                    Sensitivity::High,
                    &mut rendered,
                );
            } else {
                rendered.write_str(fragment.as_str());
            }
        }

        let status = if components.is_empty() {
            UriRedactionStatus::PassedThrough
        } else {
            UriRedactionStatus::Redacted
        };
        let (safe, truncated) = rendered.finish();
        if truncated {
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
    rendered: &mut BoundedUriWriter,
) -> Result<(), ()> {
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        rendered.write_str(authority);
        return Ok(());
    };
    let Some((username, password)) = userinfo.split_once(':') else {
        redact_userinfo_value(
            userinfo,
            "username",
            UriComponent::Username,
            policy,
            reasons,
            components,
            rendered,
        )?;
        rendered.write_str("@");
        rendered.write_str(host);
        return Ok(());
    };
    redact_userinfo_value(
        username,
        "username",
        UriComponent::Username,
        policy,
        reasons,
        components,
        rendered,
    )?;
    rendered.write_str(":");
    redact_userinfo_value(
        password,
        "password",
        UriComponent::Password,
        policy,
        reasons,
        components,
        rendered,
    )?;
    rendered.write_str("@");
    rendered.write_str(host);
    Ok(())
}

/// Applies a named field policy to one raw userinfo component.
fn redact_userinfo_value(
    raw: &str,
    field: &str,
    component: UriComponent,
    policy: &UriRedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
    rendered: &mut BoundedUriWriter,
) -> Result<(), ()> {
    let decoded = decode_uri_component(raw).map_err(|_| ())?;
    match policy.redaction_policy().resolve_field(field) {
        ResolvedField::Sensitive { sensitivity } => {
            mark_component(component, reasons, components);
            write_sensitive_value(policy, sensitivity, &decoded, rendered);
        }
        ResolvedField::PassThrough => {
            rendered.write_str(raw);
        }
    }
    Ok(())
}

/// Redacts query values after strict percent decoding.
fn redact_query(
    query: &str,
    policy: &UriRedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
    rendered: &mut BoundedUriWriter,
) -> Result<(), UriRedactionReason> {
    for (index, pair) in query.split('&').enumerate() {
        if index != 0 {
            rendered.write_str("&");
        }
        let Some((raw_key, raw_value)) = pair.split_once('=') else {
            decode_uri_component(pair)
                .map_err(|_| UriRedactionReason::UndecodableQueryKey)?;
            rendered.write_str(pair);
            continue;
        };
        let key = decode_uri_component(raw_key)
            .map_err(|_| UriRedactionReason::UndecodableQueryKey)?;
        let value = decode_uri_component(raw_value)
            .map_err(|_| UriRedactionReason::UndecodableQueryValue)?;
        match policy.redaction_policy().resolve_field(&key) {
            ResolvedField::Sensitive { sensitivity } => {
                mark_component(UriComponent::Query, reasons, components);
                rendered.write_str(raw_key);
                rendered.write_str("=");
                write_sensitive_value(policy, sensitivity, &value, rendered);
            }
            ResolvedField::PassThrough => {
                rendered.write_str(pair);
            }
        }
    }
    Ok(())
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

/// Streams one sensitive value through URI encoding and the bounded writer.
fn write_sensitive_value(
    policy: &UriRedactionPolicy,
    sensitivity: Sensitivity,
    value: &str,
    rendered: &mut BoundedUriWriter,
) {
    if value.is_empty() || rendered.is_full() {
        return;
    }
    let mut writer = UriComponentWriter::new(rendered);
    let _ = policy
        .redaction_policy()
        .masking()
        .for_level(sensitivity)
        .write_masked(value, &mut writer);
}

/// Writes an opaque replacement without allocating beyond the output budget.
fn write_opaque_mask(
    policy: &UriRedactionPolicy,
    sensitivity: Sensitivity,
    rendered: &mut BoundedUriWriter,
) {
    if rendered.is_full() {
        return;
    }
    let mut writer = UriComponentWriter::new(rendered);
    let _ = writer.write_str(
        policy
            .redaction_policy()
            .masking()
            .for_level(sensitivity)
            .opaque_mask(),
    );
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

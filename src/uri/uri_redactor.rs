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
    RedactedText,
    RedactionPolicy,
    RedactionSession,
    Sensitivity,
    policy::ResolvedField,
};
use crate::policy::OutputCharge;

use super::{
    UriComponent,
    UriFragmentPolicy,
    UriInspection,
    UriPathPolicy,
    UriRedaction,
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
    policy: RedactionPolicy,
}

impl UriRedactor {
    /// Creates a URI redactor from an explicit immutable policy.
    #[inline]
    pub const fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Returns the immutable URI policy snapshot.
    #[must_use = "use the URI policy snapshot"]
    #[inline]
    pub const fn policy(&self) -> &RedactionPolicy {
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
            > self.policy.limits().diagnostic_event().max_input_bytes()
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
            self.policy.limits().diagnostic_event().max_output_bytes(),
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

    /// Inspects one absolute URI and returns metadata without rendering text.
    ///
    /// Parsing, strict percent decoding, and component classification follow
    /// the same URI policy as [`Self::redact_uri_str`]. The input budget still
    /// applies, while the output budget and truncation behavior do not.
    #[must_use = "use the structured URI inspection result"]
    pub fn inspect_uri_str(&self, input: &str) -> UriInspection {
        let budget = self.policy.limits().diagnostic_event();
        if input.len() > budget.max_input_bytes() {
            return invalid_inspection(UriRedactionReason::InputLimitExceeded);
        }

        let parsed = match Uri::<&str>::parse(input) {
            Ok(parsed) => parsed,
            Err(_) => {
                return invalid_inspection(UriRedactionReason::InvalidUri);
            }
        };
        let mut reasons = Vec::new();
        let mut components = Vec::new();

        if let Some(authority) = parsed.authority()
            && inspect_authority(
                authority.as_str(),
                &self.policy,
                &mut reasons,
                &mut components,
            )
            .is_err()
        {
            return invalid_inspection(UriRedactionReason::InvalidUri);
        }

        let path = parsed.path().as_str();
        if self.policy.path_policy() == UriPathPolicy::Redact
            && !path.is_empty()
            && path != "/"
        {
            mark_component(UriComponent::Path, &mut reasons, &mut components);
        }

        if let Some(query) = parsed.query()
            && let Err(reason) = inspect_query(
                query.as_str(),
                &self.policy,
                &mut reasons,
                &mut components,
            )
        {
            return invalid_inspection(reason);
        }

        if let Some(fragment) = parsed.fragment()
            && self.policy.fragment_policy() == UriFragmentPolicy::Redact
            && !fragment.as_str().is_empty()
        {
            mark_component(
                UriComponent::Fragment,
                &mut reasons,
                &mut components,
            );
        }

        let status = if components.is_empty() {
            UriRedactionStatus::PassedThrough
        } else {
            UriRedactionStatus::Redacted
        };
        UriInspection {
            status,
            reasons,
            components,
        }
    }

    /// Redacts one URI while consuming a shared diagnostic session.
    #[must_use = "use the session-bounded URI result"]
    pub fn redact_uri_str_with_session(
        &self,
        input: &str,
        session: &RedactionSession<'_>,
    ) -> UriRedaction {
        if !session.consume_input(input.len()) {
            return session_invalid_result(
                session,
                UriRedactionReason::InputLimitExceeded,
            );
        }
        let result = self.redact_uri_str(input);
        match session.charge_output_or_fallback(
            result.log_safe_text().as_str().len(),
            INVALID_URI.len(),
        ) {
            OutputCharge::Complete => result,
            OutputCharge::Fallback => {
                invalid_result(UriRedactionReason::OutputTruncated)
            }
            OutputCharge::Exhausted => empty_invalid_result(
                UriRedactionReason::OutputTruncated,
            ),
        }
    }

    /// Inspects one URI while consuming a shared diagnostic input budget.
    #[must_use = "use the session-bounded URI inspection"]
    pub fn inspect_uri_str_with_session(
        &self,
        input: &str,
        session: &RedactionSession<'_>,
    ) -> UriInspection {
        if !session.consume_input(input.len()) {
            return invalid_inspection(UriRedactionReason::InputLimitExceeded);
        }
        self.inspect_uri_str(input)
    }
}

impl Default for UriRedactor {
    /// Creates a redactor from the process-wide URI policy snapshot.
    #[inline]
    fn default() -> Self {
        Self::new(RedactionPolicy::default())
    }
}

/// Redacts userinfo while preserving the authority's raw host and port.
fn redact_authority(
    authority: &str,
    policy: &RedactionPolicy,
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

/// Inspects userinfo without allocating a rendered URI.
fn inspect_authority(
    authority: &str,
    policy: &RedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) -> Result<(), ()> {
    let Some((userinfo, _host)) = authority.rsplit_once('@') else {
        return Ok(());
    };
    let Some((username, password)) = userinfo.split_once(':') else {
        inspect_userinfo_value(
            userinfo,
            "username",
            UriComponent::Username,
            policy,
            reasons,
            components,
        )?;
        return Ok(());
    };
    inspect_userinfo_value(
        username,
        "username",
        UriComponent::Username,
        policy,
        reasons,
        components,
    )?;
    inspect_userinfo_value(
        password,
        "password",
        UriComponent::Password,
        policy,
        reasons,
        components,
    )?;
    Ok(())
}

/// Applies a named field policy to one userinfo component without rendering.
fn inspect_userinfo_value(
    raw: &str,
    field: &str,
    component: UriComponent,
    policy: &RedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) -> Result<(), ()> {
    decode_uri_component(raw).map_err(|_| ())?;
    if matches!(policy.resolve_field(field), ResolvedField::Sensitive { .. }) {
        mark_component(component, reasons, components);
    }
    Ok(())
}

/// Applies a named field policy to one raw userinfo component.
fn redact_userinfo_value(
    raw: &str,
    field: &str,
    component: UriComponent,
    policy: &RedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
    rendered: &mut BoundedUriWriter,
) -> Result<(), ()> {
    let decoded = decode_uri_component(raw).map_err(|_| ())?;
    match policy.resolve_field(field) {
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
    policy: &RedactionPolicy,
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
        match policy.resolve_field(&key) {
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

/// Inspects query fields after strict percent decoding without rendering.
fn inspect_query(
    query: &str,
    policy: &RedactionPolicy,
    reasons: &mut Vec<UriRedactionReason>,
    components: &mut Vec<UriComponent>,
) -> Result<(), UriRedactionReason> {
    for pair in query.split('&') {
        let Some((raw_key, raw_value)) = pair.split_once('=') else {
            decode_uri_component(pair)
                .map_err(|_| UriRedactionReason::UndecodableQueryKey)?;
            continue;
        };
        let key = decode_uri_component(raw_key)
            .map_err(|_| UriRedactionReason::UndecodableQueryKey)?;
        decode_uri_component(raw_value)
            .map_err(|_| UriRedactionReason::UndecodableQueryValue)?;
        if matches!(policy.resolve_field(&key), ResolvedField::Sensitive { .. })
        {
            mark_component(UriComponent::Query, reasons, components);
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
    policy: &RedactionPolicy,
    sensitivity: Sensitivity,
    value: &str,
    rendered: &mut BoundedUriWriter,
) {
    if value.is_empty() || rendered.is_full() {
        return;
    }
    let mut writer = UriComponentWriter::new(rendered);
    let _ = policy
        .masking()
        .for_level(sensitivity)
        .write_masked(value, &mut writer);
}

/// Writes an opaque replacement without allocating beyond the output budget.
fn write_opaque_mask(
    policy: &RedactionPolicy,
    sensitivity: Sensitivity,
    rendered: &mut BoundedUriWriter,
) {
    if rendered.is_full() {
        return;
    }
    let mut writer = UriComponentWriter::new(rendered);
    let _ =
        writer.write_str(policy.masking().for_level(sensitivity).opaque_mask());
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

/// Charges the invalid-URI marker once for a shared diagnostic session.
fn session_invalid_result(
    session: &RedactionSession<'_>,
    reason: UriRedactionReason,
) -> UriRedaction {
    match session.charge_output_or_fallback(INVALID_URI.len(), INVALID_URI.len())
    {
        OutputCharge::Complete => invalid_result(reason),
        OutputCharge::Fallback | OutputCharge::Exhausted => {
            empty_invalid_result(reason)
        }
    }
}

/// Preserves fail-closed metadata without emitting bytes after exhaustion.
fn empty_invalid_result(reason: UriRedactionReason) -> UriRedaction {
    UriRedaction {
        text: safe_text(String::new()),
        status: UriRedactionStatus::Invalid,
        reasons: vec![reason],
        components: Vec::new(),
        truncated: true,
    }
}

/// Builds metadata for malformed or over-budget input.
fn invalid_inspection(reason: UriRedactionReason) -> UriInspection {
    UriInspection {
        status: UriRedactionStatus::Invalid,
        reasons: vec![reason],
        components: Vec::new(),
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

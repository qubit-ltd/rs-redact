// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded URI rendering used by the shared redaction session.

use std::borrow::Cow;
use std::fmt::Write;

use fluent_uri::Uri;

use super::UriFragmentPolicy;
use super::UriPathPolicy;
use super::internal::BoundedUriWriter;
use super::internal::UriComponentWriter;
use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::output::log_escape::escape_log_control_characters;
use crate::policy::ResolvedField;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;

/// Safe replacement used when URI parsing or decoding fails.
const INVALID_URI: &str = "<invalid URI>";

/// Renders one URI under the output ceiling supplied by its parent session.
///
/// This function owns neither a policy snapshot nor a budget. It returns the
/// unpublished renderer carrier, so URI rendering cannot publish a second
/// result model or make an independent completion decision.
#[must_use]
pub(crate) fn redact_uri_with_limit(
    policy: &RedactionPolicy,
    input: &str,
    max_output_bytes: usize,
) -> RenderedOperation {
    let parsed = match Uri::<&str>::parse(input) {
        Ok(parsed) => parsed,
        Err(_) => return invalid_output(max_output_bytes),
    };
    let mut rendered = BoundedUriWriter::new(max_output_bytes);
    let scheme = parsed.scheme().as_str();
    let scheme_end = scheme.len() + 1;
    rendered.write_str(&input[..scheme_end]);

    if let Some(authority) = parsed.authority() {
        rendered.write_str("//");
        if redact_authority(authority.as_str(), policy, &mut rendered).is_err() {
            return invalid_output(max_output_bytes);
        }
        if rendered.is_full() {
            return finish_uri_rendering(rendered);
        }
    }

    let path = parsed.path().as_str();
    if policy.path_policy() == UriPathPolicy::Redact && !path.is_empty() && path != "/" {
        if path.starts_with('/') {
            rendered.write_str("/%3Credacted%3E");
        } else {
            rendered.write_str("%3Credacted%3E");
        }
    } else {
        rendered.write_str(path);
    }
    if rendered.is_full() {
        return finish_uri_rendering(rendered);
    }

    if let Some(query) = parsed.query() {
        rendered.write_str("?");
        if redact_query(query.as_str(), policy, &mut rendered).is_err() {
            return invalid_output(max_output_bytes);
        }
        if rendered.is_full() {
            return finish_uri_rendering(rendered);
        }
    }

    if let Some(fragment) = parsed.fragment() {
        rendered.write_str("#");
        if policy.fragment_policy() == UriFragmentPolicy::Redact && !fragment.as_str().is_empty() {
            write_opaque_mask(policy, Sensitivity::High, &mut rendered);
        } else {
            rendered.write_str(fragment.as_str());
        }
    }

    finish_uri_rendering(rendered)
}

/// Converts bounded URI bytes to the runtime's single output carrier.
#[must_use]
fn finish_uri_rendering(rendered: BoundedUriWriter) -> RenderedOperation {
    let (rendered, completion) = rendered.finish_with_completion(true);
    let text = safe_text(rendered);
    match completion {
        RedactionCompletion::Complete => OperationSink::complete(text).finish(),
        RedactionCompletion::Truncated | RedactionCompletion::Exhausted => {
            OperationSink::truncated(text, RedactionReason::OutputLimitReached).finish()
        }
    }
}

/// Emits a bounded marker for invalid URI input without retaining input bytes.
#[must_use]
fn invalid_output(max_output_bytes: usize) -> RenderedOperation {
    if INVALID_URI.len() <= max_output_bytes {
        return OperationSink::complete_with_reason(safe_text(INVALID_URI.to_owned()), RedactionReason::InvalidUri)
            .finish();
    }
    OperationSink::truncated(String::new(), RedactionReason::OutputLimitReached)
        .with_reason(RedactionReason::InvalidUri)
        .finish()
}

/// Redacts userinfo while preserving the authority's raw host and port.
fn redact_authority(authority: &str, policy: &RedactionPolicy, rendered: &mut BoundedUriWriter) -> Result<(), ()> {
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        rendered.write_str(authority);
        return Ok(());
    };
    let Some((username, password)) = userinfo.split_once(':') else {
        redact_userinfo_value(userinfo, "username", policy, rendered)?;
        rendered.write_str("@");
        if rendered.is_full() {
            return Ok(());
        }
        rendered.write_str(host);
        return Ok(());
    };
    redact_userinfo_value(username, "username", policy, rendered)?;
    rendered.write_str(":");
    if rendered.is_full() {
        return Ok(());
    }
    redact_userinfo_value(password, "password", policy, rendered)?;
    rendered.write_str("@");
    if rendered.is_full() {
        return Ok(());
    }
    rendered.write_str(host);
    Ok(())
}

/// Applies the core field policy to one raw userinfo component.
fn redact_userinfo_value(
    raw: &str,
    field: &str,
    policy: &RedactionPolicy,
    rendered: &mut BoundedUriWriter,
) -> Result<(), ()> {
    let decoded = decode_uri_component(raw)?;
    match policy.resolve_field(field) {
        ResolvedField::Sensitive { sensitivity } => {
            write_sensitive_value(policy, sensitivity, &decoded, rendered);
        }
        ResolvedField::PassThrough => {
            rendered.write_str(raw);
        }
    }
    Ok(())
}

/// Redacts query values after strict percent decoding.
fn redact_query(query: &str, policy: &RedactionPolicy, rendered: &mut BoundedUriWriter) -> Result<(), ()> {
    for (index, pair) in query.split('&').enumerate() {
        if rendered.is_full() {
            return Ok(());
        }
        if index != 0 {
            rendered.write_str("&");
        }
        let Some((raw_key, raw_value)) = pair.split_once('=') else {
            decode_uri_component(pair)?;
            rendered.write_str(pair);
            continue;
        };
        let key = decode_uri_component(raw_key)?;
        let value = decode_uri_component(raw_value)?;
        match policy.resolve_field(&key) {
            ResolvedField::Sensitive { sensitivity } => {
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
    policy: &RedactionPolicy,
    sensitivity: Sensitivity,
    value: &str,
    rendered: &mut BoundedUriWriter,
) {
    if value.is_empty() || rendered.is_full() {
        return;
    }
    let mut writer = UriComponentWriter::new(rendered);
    let _ = policy.masking().for_level(sensitivity).write_masked(value, &mut writer);
}

/// Writes an opaque replacement without allocating beyond the output budget.
fn write_opaque_mask(policy: &RedactionPolicy, sensitivity: Sensitivity, rendered: &mut BoundedUriWriter) {
    if rendered.is_full() {
        return;
    }
    let mut writer = UriComponentWriter::new(rendered);
    let _ = writer.write_str(policy.masking().for_level(sensitivity).opaque_mask());
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

/// Converts owned output into the library's log-safe text wrapper.
#[must_use]
fn safe_text(value: String) -> String {
    escape_log_control_characters(Cow::Owned(value)).into_owned()
}

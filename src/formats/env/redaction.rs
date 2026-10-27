// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Environment-variable pair and assignment redaction.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Write as _;

use crate::RedactionReason;
use crate::Sensitivity;
use crate::formats::internal::bounded_os_text;
use crate::policy::RedactionPolicy;
use crate::policy::ResolvedField;
use crate::runtime::OperationByteSink;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;

/// Redacts one UTF-8 environment-variable pair with a borrowed policy.
///
/// The shared-session façade uses this helper so it never constructs a second
/// core redactor or a separate output budget.
#[inline]
pub(super) fn redact_pair_with_policy(
    policy: &RedactionPolicy,
    name: &str,
    value: &str,
    max_output_bytes: usize,
) -> RenderedOperation {
    render_pair_output(policy, OsStr::new(name), OsStr::new(value), max_output_bytes)
}

/// Redacts environment pairs with a borrowed policy.
///
/// The aggregate session supplies the parent policy through this helper and
/// applies its one global output budget when it commits the returned text.
pub(crate) fn redact_os_pairs_with_policy<'a, I>(
    policy: &RedactionPolicy,
    pairs: I,
    max_output_bytes: usize,
) -> RenderedOperation
where
    I: IntoIterator<Item = (&'a OsStr, &'a OsStr)>,
{
    let mut writer = OperationByteSink::new(max_output_bytes);
    if writer.write_char('[').is_err() {
        return truncated_output(max_output_bytes);
    }
    let mut has_item = false;
    let mut locally_truncated = false;
    for (name, value) in pairs {
        let (pair, truncated) = redact_os_pair_bounded_with_policy(policy, name, value, max_output_bytes);
        locally_truncated |= truncated;
        if (has_item && writer.write_str(", ").is_err()) || write!(&mut writer, "{pair:?}").is_err() {
            locally_truncated = true;
            break;
        }
        has_item = true;
    }
    if locally_truncated {
        const FALLBACK: &str = "<truncated>";
        return if FALLBACK.len() <= max_output_bytes {
            OperationSink::truncated(FALLBACK, RedactionReason::OutputLimitReached).finish()
        } else {
            OperationSink::truncated("", RedactionReason::OutputLimitReached).finish()
        };
    }
    if writer.write_char(']').is_err() {
        return truncated_output(max_output_bytes);
    }
    let Some(writer) = writer.into_string() else {
        return truncated_output(max_output_bytes);
    };
    OperationSink::complete(writer).finish()
}

/// Returns the existing output-limit fallback for an unpublished env list.
fn truncated_output(max_output_bytes: usize) -> RenderedOperation {
    const FALLBACK: &str = "<truncated>";
    if FALLBACK.len() <= max_output_bytes {
        OperationSink::truncated(FALLBACK, RedactionReason::OutputLimitReached).finish()
    } else {
        OperationSink::truncated("", RedactionReason::OutputLimitReached).finish()
    }
}

/// Renders one unpublished environment assignment without materializing a
/// separately publishable pair result.
fn render_pair_output(
    policy: &RedactionPolicy,
    name: &OsStr,
    value: &OsStr,
    max_output_bytes: usize,
) -> RenderedOperation {
    let (rendered, locally_truncated) = redact_os_pair_bounded_with_policy(policy, name, value, max_output_bytes);
    let mut writer = OperationByteSink::new(max_output_bytes);
    if locally_truncated || writer.write_str(&rendered).is_err() {
        return truncated_output(max_output_bytes);
    }
    let Some(rendered) = writer.into_string() else {
        return truncated_output(max_output_bytes);
    };
    OperationSink::complete(rendered).finish()
}

/// Renders one environment pair while bounding its materialized mask.
#[must_use]
pub(super) fn redact_os_pair_bounded_with_policy(
    policy: &RedactionPolicy,
    name: &OsStr,
    value: &OsStr,
    max_mask_bytes: usize,
) -> (String, bool) {
    let (pair, locally_truncated) = match (name.to_str(), value.to_str()) {
        (Some(name), Some(value)) => {
            let resolved = if policy.is_disabled() {
                ResolvedField::PassThrough
            } else {
                policy.resolve_field(name)
            };
            let (value, locally_truncated) = match resolved {
                ResolvedField::Sensitive { sensitivity } => {
                    let (masked, truncated) =
                        policy
                            .masking()
                            .mask_bounded_with_truncation(sensitivity, value, max_mask_bytes);
                    (masked, truncated)
                }
                ResolvedField::PassThrough => (Cow::Borrowed(value), false),
            };
            let mut pair = String::with_capacity(max_mask_bytes.min(1024));
            let complete = append_log_safe_bounded(name, &mut pair, max_mask_bytes)
                && append_log_safe_bounded("=", &mut pair, max_mask_bytes)
                && append_log_safe_bounded(&value, &mut pair, max_mask_bytes);
            (pair, locally_truncated || !complete)
        }
        _ if policy.is_disabled() => {
            let (name, name_truncated) = bounded_os_text::capture(name, max_mask_bytes);
            if name_truncated {
                return (String::new(), true);
            }
            let value_limit = max_mask_bytes.saturating_sub(name.len()).saturating_sub(1);
            let (value, value_truncated) = bounded_os_text::capture(value, value_limit);
            let mut pair = String::with_capacity(max_mask_bytes.min(1024));
            let complete = !value_truncated
                && append_log_safe_bounded(&name, &mut pair, max_mask_bytes)
                && append_log_safe_bounded("=", &mut pair, max_mask_bytes)
                && append_log_safe_bounded(&value, &mut pair, max_mask_bytes);
            (pair, !complete)
        }
        _ => {
            let masking = policy.masking();
            let complete_len = masking.mask_opaque(Sensitivity::Secret).len();
            let masked = masking.mask_opaque_bounded(Sensitivity::Secret, max_mask_bytes);
            let locally_truncated = masked.len() < complete_len;
            let (name, name_truncated) = bounded_os_text::capture(name, max_mask_bytes);
            let mut pair = String::with_capacity(max_mask_bytes.min(1024));
            let complete = !name_truncated
                && append_log_safe_bounded(&name, &mut pair, max_mask_bytes)
                && append_log_safe_bounded("=", &mut pair, max_mask_bytes)
                && append_log_safe_bounded(&masked, &mut pair, max_mask_bytes);
            (pair, locally_truncated || !complete)
        }
    };
    (pair, locally_truncated)
}

/// Appends log-safe text without retaining bytes beyond the operation limit.
fn append_log_safe_bounded(value: &str, output: &mut String, maximum: usize) -> bool {
    let mut encoded = [0_u8; 12];
    for character in value.chars() {
        let Ok(piece) = crate::output::log_escape::encode_log_safe_character(character, &mut encoded) else {
            return false;
        };
        if output.len().saturating_add(piece.len()) > maximum {
            return false;
        }
        output.push_str(piece);
    }
    true
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use super::redact_os_pair_bounded_with_policy;
    use crate::RedactionPolicy;

    /// Covers enabled and disabled handling of non-UTF-8 environment values.
    #[cfg(unix)]
    #[test]
    fn test_environment_rendering_handles_non_utf8_pairs_by_policy() {
        let name = OsString::from_vec(vec![b'N', 0xff]);
        let value = OsString::from_vec(vec![b'V', 0xff]);

        let (enabled, enabled_truncated) =
            redact_os_pair_bounded_with_policy(&RedactionPolicy::standard(), &name, &value, usize::MAX);
        assert!(!enabled_truncated);
        assert!(enabled.contains("redacted"));

        let (disabled, disabled_truncated) =
            redact_os_pair_bounded_with_policy(&RedactionPolicy::disabled(), &name, &value, usize::MAX);
        assert!(!disabled_truncated);
        assert!(disabled.contains('N'));
        assert!(disabled.contains('V'));
    }
}

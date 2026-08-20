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

use crate::RedactionReason;
use crate::Sensitivity;
use crate::output::log_escape::escape_log_control_characters;
use crate::policy::RedactionPolicy;
use crate::policy::ResolvedField;
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
    let mut writer = String::from("[");
    let mut has_item = false;
    let mut locally_truncated = false;
    for (name, value) in pairs {
        let (pair, truncated) = redact_os_pair_bounded_with_policy(policy, name, value, max_output_bytes);
        locally_truncated |= truncated;
        let separator_len = usize::from(has_item) * 2;
        let rendered_len = format!("{pair:?}").len();
        if writer
            .len()
            .saturating_add(separator_len)
            .saturating_add(rendered_len)
            .saturating_add(1)
            > max_output_bytes
        {
            locally_truncated = true;
            break;
        }
        write_debug_item(&mut writer, &mut has_item, &pair);
    }
    if locally_truncated {
        const FALLBACK: &str = "<truncated>";
        return if FALLBACK.len() <= max_output_bytes {
            RenderedOperation::truncated(FALLBACK, RedactionReason::OutputLimitReached)
        } else {
            RenderedOperation::truncated("", RedactionReason::OutputLimitReached)
        };
    }
    if writer.len().saturating_add(1) > max_output_bytes {
        const FALLBACK: &str = "<truncated>";
        return if FALLBACK.len() <= max_output_bytes {
            RenderedOperation::truncated(FALLBACK, RedactionReason::OutputLimitReached)
        } else {
            RenderedOperation::truncated("", RedactionReason::OutputLimitReached)
        };
    }
    writer.push(']');
    RenderedOperation::complete(writer)
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
    if locally_truncated || rendered.len() > max_output_bytes {
        const FALLBACK: &str = "<truncated>";
        return if FALLBACK.len() <= max_output_bytes {
            RenderedOperation::truncated(FALLBACK, RedactionReason::OutputLimitReached)
        } else {
            RenderedOperation::truncated("", RedactionReason::OutputLimitReached)
        };
    }
    RenderedOperation::complete(rendered)
}

/// Renders one environment pair while bounding its materialized mask.
pub(super) fn redact_os_pair_bounded_with_policy(
    policy: &RedactionPolicy,
    name: &OsStr,
    value: &OsStr,
    max_mask_bytes: usize,
) -> (String, bool) {
    let (pair, locally_truncated) = match (name.to_str(), value.to_str()) {
        (Some(name), Some(value)) => {
            let resolved = policy.resolve_field(name);
            let (value, locally_truncated) = match resolved {
                ResolvedField::Sensitive { sensitivity } => {
                    let (masked, truncated) =
                        policy
                            .masking()
                            .mask_bounded_with_truncation(sensitivity, value, max_mask_bytes);
                    (masked.into_owned(), truncated)
                }
                ResolvedField::PassThrough => (value.to_owned(), false),
            };
            (
                format!(
                    "{}={}",
                    log_safe_owned(name.to_owned()).as_str(),
                    log_safe_owned(value).as_str()
                ),
                locally_truncated,
            )
        }
        _ => {
            let masking = policy.masking();
            let complete_len = masking.mask_opaque(Sensitivity::Secret).len();
            let masked = masking.mask_opaque_bounded(Sensitivity::Secret, max_mask_bytes);
            let locally_truncated = masked.len() < complete_len;
            (
                format!(
                    "{}={}",
                    log_safe_owned(name.to_string_lossy().into_owned()).as_str(),
                    log_safe_owned(masked).as_str(),
                ),
                locally_truncated,
            )
        }
    };
    (pair, locally_truncated)
}

/// Escapes an owned string and labels it safe for text-log display.
///
/// # Parameters
///
/// * `value` - Owned text to escape.
///
/// # Returns
///
/// An owned typed log-safe value.
#[inline(always)]
#[must_use]
fn log_safe_owned(value: String) -> String {
    escape_log_control_characters(Cow::Owned(value)).into_owned()
}

/// Appends one redacted assignment to a bounded debug-style list.
///
/// # Parameters
///
/// * `writer` - Escaped bounded output destination.
/// * `has_item` - Whether a preceding list item has already been rendered.
/// * `item` - Redacted assignment safe to format.
pub(super) fn write_debug_item(writer: &mut String, has_item: &mut bool, item: &str) {
    if *has_item {
        writer.push_str(", ");
    }
    writer.push_str(&format!("{item:?}"));
    *has_item = true;
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explicit and heuristic argument-vector redaction.

use std::ffi::OsStr;

use super::ArgvItem;
use super::pending_field::PendingField;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::policy::RedactionPolicy;
use crate::policy::ResolvedField;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;

/// Redacts explicitly classified argv items with the supplied session policy.
///
/// The returned renderer state remains unpublished until its parent
/// transaction commits it. `max_output_bytes` is the parent session's
/// remaining capacity, never an independent adapter budget.
pub(crate) fn redact_items_with_policy<'a, I>(
    policy: &RedactionPolicy,
    items: I,
    max_output_bytes: usize,
) -> RenderedOperation
where
    I: IntoIterator<Item = ArgvItem<'a>>,
{
    render_direct(policy, items, false, max_output_bytes)
}

/// Redacts heuristically classified argv items with the supplied session
/// policy and remaining shared capacity.
pub(crate) fn redact_heuristically_with_policy<'a, I>(
    policy: &RedactionPolicy,
    items: I,
    max_output_bytes: usize,
) -> RenderedOperation
where
    I: IntoIterator<Item = ArgvItem<'a>>,
{
    render_direct(policy, items, true, max_output_bytes)
}

/// Renders a finite argv iterator with one immutable policy snapshot.
fn render_direct<'a, I>(
    policy: &RedactionPolicy,
    items: I,
    heuristic: bool,
    max_output_bytes: usize,
) -> RenderedOperation
where
    I: IntoIterator<Item = ArgvItem<'a>>,
{
    let mut writer = String::from("[");
    let mut has_item = false;
    let mut pending = None;
    let mut locally_truncated = false;
    for item in items {
        let (rendered, item_truncated) = if heuristic {
            if let Some(level) = item.sensitivity() {
                pending = None;
                mask_os_value_bounded(policy, item.value(), level, max_output_bytes)
            } else {
                redact_plain_item_bounded(policy, item.value(), &mut pending, max_output_bytes)
            }
        } else {
            render_explicit_or_plain_bounded(policy, item, max_output_bytes)
        };
        locally_truncated |= item_truncated;
        let separator = if has_item { ", " } else { "" };
        let rendered = format!("{rendered:?}");
        if writer
            .len()
            .saturating_add(separator.len())
            .saturating_add(rendered.len())
            .saturating_add(1)
            > max_output_bytes
        {
            locally_truncated = true;
            break;
        }
        writer.push_str(separator);
        writer.push_str(&rendered);
        has_item = true;
    }
    if locally_truncated {
        return truncated_output(max_output_bytes);
    }
    if writer.len().saturating_add(1) > max_output_bytes {
        return truncated_output(max_output_bytes);
    }
    writer.push(']');
    OperationSink::complete(writer).finish()
}

/// Returns unpublished fallback text when argv rendering cannot retain its
/// complete representation within the parent transaction's capacity.
fn truncated_output(max_output_bytes: usize) -> RenderedOperation {
    const FALLBACK: &str = "<truncated>";
    if FALLBACK.len() <= max_output_bytes {
        OperationSink::truncated(FALLBACK, RedactionReason::OutputLimitReached).finish()
    } else {
        OperationSink::truncated("", RedactionReason::OutputLimitReached).finish()
    }
}

/// Renders an explicitly classified or plain argv item.
fn render_explicit_or_plain_bounded(
    policy: &RedactionPolicy,
    item: ArgvItem<'_>,
    max_output_bytes: usize,
) -> (String, bool) {
    match item.sensitivity() {
        Some(level) => mask_os_value_bounded(policy, item.value(), level, max_output_bytes),
        None => (item.value().to_string_lossy().into_owned(), false),
    }
}

/// Masks an operating-system argv value with an explicit output ceiling.
fn mask_os_value_bounded(
    policy: &RedactionPolicy,
    value: &OsStr,
    level: Sensitivity,
    max_output_bytes: usize,
) -> (String, bool) {
    match value.to_str() {
        Some(value) => {
            let (masked, truncated) = policy
                .masking()
                .mask_bounded_with_truncation(level, value, max_output_bytes);
            (masked.into_owned(), truncated)
        }
        None => mask_opaque_value_bounded(policy, max_output_bytes),
    }
}

/// Redacts one heuristically classified plain argv item.
fn redact_plain_item_bounded(
    policy: &RedactionPolicy,
    value: &OsStr,
    pending_field: &mut Option<PendingField>,
    max_output_bytes: usize,
) -> (String, bool) {
    let Some(value) = value.to_str() else {
        *pending_field = Some(PendingField {
            field: String::new(),
            exact: false,
        });
        return mask_opaque_value_bounded(policy, max_output_bytes);
    };

    let option = option_field(value);
    if let Some(pending) = pending_field.take() {
        if let Some((field, exact)) = option
            && option_is_sensitive(policy, field, exact)
        {
            *pending_field = Some(PendingField {
                field: field.to_owned(),
                exact,
            });
        }
        if pending.field.is_empty() {
            return mask_opaque_value_bounded(policy, max_output_bytes);
        }
        return mask_pending_value_bounded(policy, &pending, value, max_output_bytes);
    }
    if let Some(value) = redact_assignment_bounded(policy, value, max_output_bytes) {
        return value;
    }
    if let Some(value) = redact_inline_option_bounded(policy, value, max_output_bytes) {
        return value;
    }
    if let Some(value) = redact_jvm_property_bounded(policy, value, max_output_bytes) {
        return value;
    }
    if let Some((field, exact)) = option
        && option_is_sensitive(policy, field, exact)
    {
        *pending_field = Some(PendingField {
            field: field.to_owned(),
            exact,
        });
    }
    (value.to_owned(), false)
}

/// Resolves a possible option field name and its matching mode.
fn option_field(value: &str) -> Option<(&str, bool)> {
    let name = option_name(value)?;
    Some((name, !value.starts_with("--")))
}

/// Returns whether a policy classifies an option field as sensitive.
fn option_is_sensitive(policy: &RedactionPolicy, field: &str, exact: bool) -> bool {
    if exact {
        policy.sensitivity_for_exact(field).is_some()
    } else {
        policy.sensitivity_for(field).is_some()
    }
}

/// Redacts a `NAME=value` assignment when its name is sensitive.
fn redact_assignment_bounded(policy: &RedactionPolicy, value: &str, max_output_bytes: usize) -> Option<(String, bool)> {
    if value.starts_with('-') {
        return None;
    }
    let (name, raw_value) = value.split_once('=')?;
    if name.is_empty() {
        return None;
    }
    let (redacted, truncated) = mask_field_value_bounded(policy, name, raw_value, max_output_bytes)?;
    Some((format!("{name}={redacted}"), truncated))
}

/// Redacts a `--name=value` option when its name is sensitive.
fn redact_inline_option_bounded(
    policy: &RedactionPolicy,
    value: &str,
    max_output_bytes: usize,
) -> Option<(String, bool)> {
    if !value.starts_with("--") {
        return None;
    }
    let (left, raw_value) = value.split_once('=')?;
    let name = option_name(left)?;
    let (redacted, truncated) = mask_field_value_bounded(policy, name, raw_value, max_output_bytes)?;
    Some((format!("{left}={redacted}"), truncated))
}

/// Redacts a `-Dname=value` JVM property when its name is sensitive.
fn redact_jvm_property_bounded(
    policy: &RedactionPolicy,
    value: &str,
    max_output_bytes: usize,
) -> Option<(String, bool)> {
    let property = value.strip_prefix("-D")?;
    let (name, raw_value) = property.split_once('=')?;
    if name.is_empty() {
        return None;
    }
    let (redacted, truncated) = mask_field_value_bounded(policy, name, raw_value, max_output_bytes)?;
    Some((format!("-D{name}={redacted}"), truncated))
}

/// Masks the value following a sensitive option.
fn mask_pending_value_bounded(
    policy: &RedactionPolicy,
    pending: &PendingField,
    value: &str,
    max_output_bytes: usize,
) -> (String, bool) {
    let resolved = if pending.exact {
        policy.resolve_field_exact(&pending.field)
    } else {
        policy.resolve_field(&pending.field)
    };
    match resolved {
        ResolvedField::Sensitive { sensitivity } => {
            let (masked, truncated) =
                policy
                    .masking()
                    .mask_bounded_with_truncation(sensitivity, value, max_output_bytes);
            (masked.into_owned(), truncated)
        }
        ResolvedField::PassThrough => (value.to_owned(), false),
    }
}

/// Masks one classified field, returning `None` for pass-through fields.
fn mask_field_value_bounded(
    policy: &RedactionPolicy,
    field: &str,
    value: &str,
    max_output_bytes: usize,
) -> Option<(String, bool)> {
    match policy.resolve_field(field) {
        ResolvedField::Sensitive { sensitivity } => {
            let (masked, truncated) =
                policy
                    .masking()
                    .mask_bounded_with_truncation(sensitivity, value, max_output_bytes);
            Some((masked.into_owned(), truncated))
        }
        ResolvedField::PassThrough => None,
    }
}

/// Produces a bounded opaque secret replacement.
fn mask_opaque_value_bounded(policy: &RedactionPolicy, max_output_bytes: usize) -> (String, bool) {
    let masking = policy.masking();
    let complete_len = masking.mask_opaque(Sensitivity::Secret).len();
    let masked = masking.mask_opaque_bounded(Sensitivity::Secret, max_output_bytes);
    let truncated = masked.len() < complete_len;
    (masked, truncated)
}

/// Returns an option name without its leading dashes.
#[inline]
fn option_name(value: &str) -> Option<&str> {
    if !value.starts_with('-') || value == "-" || value.contains('=') {
        return None;
    }
    let name = value.trim_start_matches('-');
    if name.is_empty() { None } else { Some(name) }
}

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
        let (rendered, item_truncated) = if policy.is_disabled() {
            pending = None;
            (item.value().to_string_lossy().into_owned(), false)
        } else if heuristic {
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
            let (masked, truncated) =
                policy
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
fn redact_assignment_bounded(
    policy: &RedactionPolicy,
    value: &str,
    max_output_bytes: usize,
) -> Option<(String, bool)> {
    if value.starts_with('-') {
        return None;
    }
    let (name, raw_value) = value.split_once('=')?;
    if name.is_empty() {
        return None;
    }
    let (redacted, truncated) =
        mask_field_value_bounded(policy, name, raw_value, max_output_bytes)?;
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
    let (redacted, truncated) =
        mask_field_value_bounded(policy, name, raw_value, max_output_bytes)?;
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
    let (redacted, truncated) =
        mask_field_value_bounded(policy, name, raw_value, max_output_bytes)?;
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

/// Classifies one heuristic argv item without materializing a mask.
#[must_use]
pub(super) fn inspect_heuristic_item(
    policy: &RedactionPolicy,
    item: ArgvItem<'_>,
    pending_field: &mut Option<PendingField>,
) -> Option<Sensitivity> {
    if let Some(sensitivity) = item.sensitivity() {
        *pending_field = None;
        return Some(sensitivity);
    }
    let Some(value) = item.value().to_str() else {
        *pending_field = Some(PendingField {
            field: String::new(),
            exact: false,
        });
        return Some(Sensitivity::Secret);
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
            return Some(Sensitivity::Secret);
        }
        return match if pending.exact {
            policy.resolve_field_exact(&pending.field)
        } else {
            policy.resolve_field(&pending.field)
        } {
            ResolvedField::Sensitive { sensitivity } => Some(sensitivity),
            ResolvedField::PassThrough => None,
        };
    }
    let field = if !value.starts_with('-') {
        value
            .split_once('=')
            .and_then(|(field, _)| (!field.is_empty()).then_some(field))
    } else if let Some(property) = value.strip_prefix("-D") {
        property
            .split_once('=')
            .and_then(|(field, _)| (!field.is_empty()).then_some(field))
    } else if value.starts_with("--") {
        value
            .split_once('=')
            .and_then(|(left, _)| option_name(left))
    } else {
        None
    };
    if let Some(field) = field
        && let ResolvedField::Sensitive { sensitivity } = policy.resolve_field(field)
    {
        return Some(sensitivity);
    }
    if let Some((field, exact)) = option
        && option_is_sensitive(policy, field, exact)
    {
        *pending_field = Some(PendingField {
            field: field.to_owned(),
            exact,
        });
    }
    None
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

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use super::ArgvItem;
    use super::PendingField;
    use super::inspect_heuristic_item;
    use super::redact_heuristically_with_policy;
    use crate::RedactionCompletion;
    use crate::RedactionPolicy;
    use crate::Sensitivity;

    /// Covers explicit metadata, assignments, inline options, JVM properties,
    /// and replacement of a pending sensitive option.
    #[test]
    fn heuristic_rendering_covers_supported_sensitive_shapes() {
        let policy = RedactionPolicy::standard();
        let output = redact_heuristically_with_policy(
            &policy,
            [
                ArgvItem::sensitive(OsStr::new("explicit"), Sensitivity::Secret),
                ArgvItem::plain(OsStr::new("password=assignment")),
                ArgvItem::plain(OsStr::new("--token=inline")),
                ArgvItem::plain(OsStr::new("-Dpassword=jvm")),
                ArgvItem::plain(OsStr::new("--password")),
                ArgvItem::plain(OsStr::new("--token")),
                ArgvItem::plain(OsStr::new("pending")),
                ArgvItem::plain(OsStr::new("=plain")),
                ArgvItem::plain(OsStr::new("-D=plain")),
            ],
            usize::MAX,
        );

        for secret in ["explicit", "assignment", "inline", "jvm", "pending"] {
            assert!(!output.text().contains(secret));
        }
        assert_eq!(output.completion(), RedactionCompletion::Complete);
    }

    /// Covers heuristic inspection state transitions and pass-through fields.
    #[test]
    fn heuristic_inspection_covers_pending_and_inline_shapes() {
        let policy = RedactionPolicy::standard();
        let mut pending = None;

        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::sensitive(OsStr::new("explicit"), Sensitivity::High),
                &mut pending,
            ),
            Some(Sensitivity::High),
        );
        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::plain(OsStr::new("password=value")),
                &mut pending
            ),
            Some(Sensitivity::Secret),
        );
        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::plain(OsStr::new("-Dpassword=value")),
                &mut pending
            ),
            Some(Sensitivity::Secret),
        );
        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::plain(OsStr::new("--password=value")),
                &mut pending
            ),
            Some(Sensitivity::Secret),
        );
        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::plain(OsStr::new("--password")),
                &mut pending
            ),
            None,
        );
        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::plain(OsStr::new("--token")),
                &mut pending
            ),
            Some(Sensitivity::Secret),
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("value")), &mut pending),
            Some(Sensitivity::High),
        );
        pending = Some(PendingField {
            field: String::from("visible"),
            exact: false,
        });
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("value")), &mut pending),
            None,
        );
    }

    /// Covers fail-closed handling for non-UTF-8 heuristic items.
    #[cfg(unix)]
    #[test]
    fn heuristic_paths_fail_closed_for_non_utf8_items() {
        let policy = RedactionPolicy::standard();
        let value = OsString::from_vec(vec![0xff]);
        let output = redact_heuristically_with_policy(
            &policy,
            [ArgvItem::plain(&value), ArgvItem::plain(OsStr::new("tail"))],
            usize::MAX,
        );
        assert!(!output.text().contains("tail"));

        let mut pending = None;
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(&value), &mut pending),
            Some(Sensitivity::Secret),
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("tail")), &mut pending),
            Some(Sensitivity::Secret),
        );
    }

    /// Covers both bounded fallback representations.
    #[test]
    fn heuristic_rendering_bounds_truncated_fallbacks() {
        let policy = RedactionPolicy::standard();
        let item = ArgvItem::plain(OsStr::new("long-visible-value"));

        let fallback = redact_heuristically_with_policy(&policy, [item], 11);
        assert_eq!(fallback.text(), "<truncated>");
        assert_eq!(fallback.completion(), RedactionCompletion::Truncated);

        let empty = redact_heuristically_with_policy(&policy, [item], 0);
        assert!(empty.text().is_empty());
        assert_eq!(empty.completion(), RedactionCompletion::Truncated);
    }
}

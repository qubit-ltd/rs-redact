// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explicit and heuristic argument-vector redaction.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Write as _;

use super::ArgvItem;
use super::internal::argv_classification::ArgvClassification;
use super::internal::bounded_join::join_bounded;
use super::internal::heuristic_classification::classify;
use super::pending_field::PendingField;
use crate::Sensitivity;
use crate::formats::internal::bounded_os_text;
use crate::policy::RedactionPolicy;
use crate::runtime::OperationByteSink;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;

/// Redacts explicitly classified argv items with the supplied session policy.
///
/// The returned renderer state remains unpublished until its parent
/// transaction commits it. `max_output_bytes` is the parent session's
/// remaining capacity, never an independent adapter budget.
///
/// # Type Parameters
///
/// - `'a`: Lifetime of the borrowed argument values.
/// - `I`: Finite iterable yielding argument items in command-line order.
///
/// # Parameters
///
/// - `policy`: Immutable redaction policy for this operation.
/// - `items`: Arguments consumed once, stopping if the output ceiling is
///   reached.
/// - `max_output_bytes`: Remaining parent-session output capacity in bytes.
///
/// # Returns
///
/// Unpublished rendered text and completion metadata for the parent
/// transaction.
#[inline]
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
///
/// # Type Parameters
///
/// - `'a`: Lifetime of the borrowed argument values.
/// - `I`: Finite iterable yielding argument items in command-line order.
///
/// # Parameters
///
/// - `policy`: Immutable redaction policy for this operation.
/// - `items`: Arguments consumed once, stopping if the output ceiling is
///   reached.
/// - `max_output_bytes`: Remaining parent-session output capacity in bytes.
///
/// # Returns
///
/// Unpublished rendered text and completion metadata for the parent
/// transaction.
#[inline]
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
///
/// # Type Parameters
///
/// - `'a`: Lifetime of the borrowed argument values.
/// - `I`: Finite iterable yielding argument items in command-line order.
///
/// # Parameters
///
/// - `policy`: Immutable redaction policy for this operation.
/// - `items`: Arguments consumed once, stopping if the output ceiling is
///   reached.
/// - `heuristic`: Whether plain arguments use heuristic classification.
/// - `max_output_bytes`: Remaining parent-session output capacity in bytes.
///
/// # Returns
///
/// Unpublished rendered text and completion metadata for the parent
/// transaction.
fn render_direct<'a, I>(
    policy: &RedactionPolicy,
    items: I,
    heuristic: bool,
    max_output_bytes: usize,
) -> RenderedOperation
where
    I: IntoIterator<Item = ArgvItem<'a>>,
{
    let mut writer = OperationByteSink::new(max_output_bytes);
    if writer.write_char('[').is_err() {
        return OperationSink::output_limit_fallback(max_output_bytes);
    }
    let mut has_item = false;
    let mut pending = None;
    let mut locally_truncated = false;
    for item in items {
        let (rendered, item_truncated) = render_item(policy, item, heuristic, &mut pending, max_output_bytes);
        locally_truncated |= item_truncated;
        let separator = if has_item { ", " } else { "" };
        if writer.write_str(separator).is_err() || write!(&mut writer, "{rendered:?}").is_err() {
            locally_truncated = true;
            break;
        }
        has_item = true;
    }
    if locally_truncated {
        return OperationSink::output_limit_fallback(max_output_bytes);
    }
    if writer.write_char(']').is_err() {
        return OperationSink::output_limit_fallback(max_output_bytes);
    }
    let Some(writer) = writer.into_string() else {
        return OperationSink::output_limit_fallback(max_output_bytes);
    };
    OperationSink::complete(writer).finish()
}

/// Applies the selected argv classification and masking policy to one item.
///
/// # Parameters
///
/// - `policy`: Policy providing classification and masking behavior.
/// - `item`: Argument with optional authoritative sensitivity.
/// - `heuristic`: Whether plain arguments use heuristic classification.
/// - `pending`: Option classification carried forward to the next item.
/// - `max_output_bytes`: Maximum bytes retained for the rendered value.
///
/// # Returns
///
/// The bounded rendered value and whether its conversion truncated it.
fn render_item<'a>(
    policy: &RedactionPolicy,
    item: ArgvItem<'a>,
    heuristic: bool,
    pending: &mut Option<PendingField>,
    max_output_bytes: usize,
) -> (Cow<'a, str>, bool) {
    if policy.is_disabled() {
        *pending = None;
        let (text, truncated) = bounded_os_text::capture(item.value(), max_output_bytes);
        return (Cow::Owned(text), truncated);
    }
    if !heuristic {
        return render_explicit_or_plain_bounded(policy, item, max_output_bytes);
    }

    match classify(policy, item, pending) {
        ArgvClassification::PassThrough(value) => {
            let (text, truncated) = bounded_os_text::capture(value, max_output_bytes);
            (Cow::Owned(text), truncated)
        }
        ArgvClassification::WholeValue { value, sensitivity } => {
            mask_os_value_bounded(policy, value, sensitivity, max_output_bytes)
        }
        ArgvClassification::InlineValue {
            assignment,
            sensitivity,
        } => {
            let (masked, mask_truncated) =
                policy
                    .masking()
                    .mask_bounded_with_truncation(sensitivity, assignment.value, max_output_bytes);
            let (joined, join_truncated) = join_bounded(&[assignment.prefix, &masked], max_output_bytes);
            (Cow::Owned(joined), mask_truncated || join_truncated)
        }
        ArgvClassification::OpaqueSecret => {
            let (masked, truncated) = mask_opaque_value_bounded(policy, max_output_bytes);
            (Cow::Owned(masked), truncated)
        }
    }
}

/// Renders an explicitly classified or plain argv item.
///
/// # Type Parameters
///
/// - `'a`: Lifetime of the borrowed argument value.
///
/// # Parameters
///
/// - `policy`: Policy providing the masking strategy.
/// - `item`: Argument with optional authoritative sensitivity.
/// - `max_output_bytes`: Maximum bytes retained for this value.
///
/// # Returns
///
/// The bounded text and whether capturing or masking truncated it.
#[must_use]
fn render_explicit_or_plain_bounded<'a>(
    policy: &RedactionPolicy,
    item: ArgvItem<'a>,
    max_output_bytes: usize,
) -> (Cow<'a, str>, bool) {
    match item.sensitivity() {
        Some(level) => mask_os_value_bounded(policy, item.value(), level, max_output_bytes),
        None => {
            let (text, truncated) = bounded_os_text::capture(item.value(), max_output_bytes);
            (Cow::Owned(text), truncated)
        }
    }
}

/// Masks an operating-system argv value with an explicit output ceiling.
///
/// # Type Parameters
///
/// - `'a`: Lifetime of the borrowed operating-system value.
///
/// # Parameters
///
/// - `policy`: Policy providing the masking strategy.
/// - `value`: Original argument; non-Unicode input is replaced opaquely.
/// - `level`: Sensitivity used for Unicode input.
/// - `max_output_bytes`: Maximum bytes retained for the replacement.
///
/// # Returns
///
/// The bounded replacement and whether it was truncated.
#[must_use]
fn mask_os_value_bounded<'a>(
    policy: &RedactionPolicy,
    value: &'a OsStr,
    level: Sensitivity,
    max_output_bytes: usize,
) -> (Cow<'a, str>, bool) {
    match value.to_str() {
        Some(value) => {
            let (masked, truncated) = policy
                .masking()
                .mask_bounded_with_truncation(level, value, max_output_bytes);
            (masked, truncated)
        }
        None => {
            let (masked, truncated) = mask_opaque_value_bounded(policy, max_output_bytes);
            (Cow::Owned(masked), truncated)
        }
    }
}

/// Produces a bounded opaque secret replacement.
///
/// # Parameters
///
/// - `policy`: Policy providing the opaque secret replacement.
/// - `max_output_bytes`: Maximum bytes retained for the replacement.
///
/// # Returns
///
/// The owned opaque secret replacement and whether it was truncated.
#[must_use]
fn mask_opaque_value_bounded(policy: &RedactionPolicy, max_output_bytes: usize) -> (String, bool) {
    let masking = policy.masking();
    let complete_len = masking.mask_opaque(Sensitivity::Secret).len();
    let masked = masking.mask_opaque_bounded(Sensitivity::Secret, max_output_bytes);
    let truncated = masked.len() < complete_len;
    (masked, truncated)
}

/// Classifies one heuristic argv item without materializing a mask.
///
/// # Parameters
///
/// - `policy`: Policy used to classify option names.
/// - `item`: Current argument, whose explicit sensitivity takes precedence.
/// - `pending_field`: Pending option classification, updated for the next item.
///
/// # Returns
///
/// `Some(level)` when this item requires masking; `None` for pass-through
/// items, including option names that only establish pending state for the next
/// item.
#[inline]
pub(super) fn inspect_heuristic_item(
    policy: &RedactionPolicy,
    item: ArgvItem<'_>,
    pending_field: &mut Option<PendingField>,
) -> Option<Sensitivity> {
    match classify(policy, item, pending_field) {
        ArgvClassification::PassThrough(_) => None,
        ArgvClassification::WholeValue { sensitivity, .. } | ArgvClassification::InlineValue { sensitivity, .. } => {
            Some(sensitivity)
        }
        ArgvClassification::OpaqueSecret => Some(Sensitivity::Secret),
    }
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
    use crate::RedactionPolicy;
    use crate::Sensitivity;

    /// Covers heuristic inspection state transitions and pass-through fields.
    #[test]
    fn test_heuristic_inspection_covers_pending_and_inline_shapes() {
        let policy = RedactionPolicy::standard();
        let mut pending = None;

        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::sensitive(OsStr::new("explicit"), Sensitivity::High),
                &mut pending,
            ),
            Some(Sensitivity::High),
            "explicit sensitivity must override heuristic classification",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("password=value")), &mut pending),
            Some(Sensitivity::Secret),
            "assignment syntax must classify its value",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("-Dpassword=value")), &mut pending),
            Some(Sensitivity::Secret),
            "JVM property syntax must classify its value",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("--password=value")), &mut pending),
            Some(Sensitivity::Secret),
            "long inline options must classify their value",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("--password")), &mut pending),
            None,
            "a sensitive option name must establish pending state",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("--token")), &mut pending),
            Some(Sensitivity::Secret),
            "consecutive options must retain the preceding protection",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("value")), &mut pending),
            Some(Sensitivity::High),
            "the pending token option must classify the following value",
        );
        pending = Some(PendingField::Classified(Sensitivity::Secret));
        assert_eq!(
            inspect_heuristic_item(
                &policy,
                ArgvItem::plain(OsStr::new("--access-key-id=weaker-inline")),
                &mut pending,
            ),
            Some(Sensitivity::Secret),
            "strong pending sensitivity must not be weakened by inline metadata",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("value")), &mut pending),
            None,
            "an inline assignment must consume the pending state",
        );
    }

    /// Covers fail-closed handling for non-UTF-8 heuristic items.
    #[cfg(unix)]
    #[test]
    fn test_heuristic_paths_fail_closed_for_non_utf8_items() {
        let policy = RedactionPolicy::standard();
        let value = OsString::from_vec(vec![0xff]);
        let mut pending = None;
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(&value), &mut pending),
            Some(Sensitivity::Secret),
            "non-Unicode input must fail closed",
        );
        assert_eq!(
            inspect_heuristic_item(&policy, ArgvItem::plain(OsStr::new("tail")), &mut pending),
            Some(Sensitivity::Secret),
            "non-Unicode input must keep the next item secret",
        );
    }
}

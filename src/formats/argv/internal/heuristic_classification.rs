// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

//! Shared argv option parsing and pending-field classification.

use crate::formats::argv::ArgvItem;
use crate::formats::argv::pending_field::PendingField;
use crate::policy::RedactionPolicy;

use super::argv_classification::ArgvClassification;
use super::inline_assignment::InlineAssignment;

/// Returns an option name without its leading dashes.
#[inline]
fn option_name(value: &str) -> Option<&str> {
    if !value.starts_with('-') || value == "-" || value.contains('=') {
        return None;
    }
    let name = value.trim_start_matches('-');
    if name.is_empty() { None } else { Some(name) }
}

/// Parses one supported inline assignment while retaining its exact prefix.
fn inline_assignment(value: &str) -> Option<InlineAssignment<'_>> {
    let (left, raw) = value.split_once('=')?;
    let field = if !value.starts_with('-') {
        (!left.is_empty()).then_some(left)?
    } else if let Some(property) = left.strip_prefix("-D") {
        (!property.is_empty()).then_some(property)?
    } else if value.starts_with("--") {
        option_name(left)?
    } else {
        return None;
    };
    Some(InlineAssignment {
        field,
        value: raw,
        prefix: &value[..left.len() + 1],
    })
}

/// Classifies one argv item and updates the pending option state.
pub(in crate::formats::argv) fn classify<'a>(
    policy: &RedactionPolicy,
    item: ArgvItem<'a>,
    pending: &mut Option<PendingField>,
) -> ArgvClassification<'a> {
    let source = item.value();
    if let Some(sensitivity) = item.sensitivity() {
        *pending = None;
        return ArgvClassification::WholeValue {
            value: source,
            sensitivity,
        };
    }
    let Some(value) = source.to_str() else {
        *pending = Some(PendingField::OpaqueSecret);
        return ArgvClassification::OpaqueSecret;
    };
    let previous = pending.take();
    if let Some(field) = option_name(value) {
        let level = if value.starts_with("--") {
            policy.sensitivity_for(field)
        } else {
            policy.sensitivity_for_exact(field)
        };
        *pending = level.map(PendingField::Classified);
    }
    let assignment = inline_assignment(value);
    if let Some(previous) = previous {
        return match previous {
            PendingField::OpaqueSecret => ArgvClassification::OpaqueSecret,
            PendingField::Classified(level) => {
                let inline = assignment
                    .as_ref()
                    .and_then(|assignment| policy.sensitivity_for(assignment.field));
                ArgvClassification::WholeValue {
                    value: source,
                    sensitivity: Some(level).max(inline).expect("pending has a level"),
                }
            }
        };
    }
    if let Some(assignment) = assignment
        && let Some(sensitivity) = policy.sensitivity_for(assignment.field)
    {
        return ArgvClassification::InlineValue {
            assignment,
            sensitivity,
        };
    }
    ArgvClassification::PassThrough(source)
}

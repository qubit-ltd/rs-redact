// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded scalar-field rendering shared by text and batch sessions.

use std::fmt::Display;
use std::fmt::Write;

use super::bounded_field_writer::BoundedFieldWriter;
use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Resolves and renders one admitted string field within an output ceiling.
#[must_use]
pub(super) fn redact_field_text_for_output(
    policy: &RedactionPolicy,
    field: &str,
    value: &str,
    max_output_bytes: usize,
) -> (String, RedactionCompletion) {
    let mut writer = BoundedFieldWriter::new(max_output_bytes);
    let result = if policy.is_disabled() {
        writer.write_str(value)
    } else {
        match policy.resolve_field(field) {
            ResolvedField::Sensitive { sensitivity } => {
                policy.masking().for_level(sensitivity).write_masked(value, &mut writer)
            }
            ResolvedField::PassThrough => writer.write_str(value),
        }
    };
    if result.is_err() || writer.overflowed() {
        return (String::new(), RedactionCompletion::Exhausted);
    }
    (writer.finish(), RedactionCompletion::Complete)
}

/// Resolves and renders one admitted display field within an output ceiling.
#[must_use]
pub(super) fn redact_field_display_for_output<T>(
    policy: &RedactionPolicy,
    field: &str,
    value: &T,
    max_output_bytes: usize,
) -> (String, RedactionCompletion)
where
    T: Display + ?Sized,
{
    let resolved = policy.resolve_field(field);
    let mut raw_writer = BoundedFieldWriter::new(max_output_bytes);
    let raw_result = match resolved {
        ResolvedField::Sensitive {
            sensitivity: Sensitivity::High | Sensitivity::Secret,
        } if !policy.is_disabled() => Ok(()),
        ResolvedField::Sensitive { .. } | ResolvedField::PassThrough => {
            Write::write_fmt(&mut raw_writer, format_args!("{value}"))
        }
    };
    if raw_result.is_err() || raw_writer.overflowed() {
        return (String::new(), RedactionCompletion::Exhausted);
    }
    if policy.is_disabled() || matches!(resolved, ResolvedField::PassThrough) {
        return (raw_writer.finish(), RedactionCompletion::Complete);
    }
    let sensitivity = match resolved {
        ResolvedField::Sensitive { sensitivity } => sensitivity,
        ResolvedField::PassThrough => {
            return (raw_writer.finish(), RedactionCompletion::Complete);
        }
    };
    let raw = raw_writer.finish();
    let mut output = BoundedFieldWriter::new(max_output_bytes);
    let result = policy.masking().for_level(sensitivity).write_masked(&raw, &mut output);
    if result.is_err() || output.overflowed() {
        return (String::new(), RedactionCompletion::Exhausted);
    }
    (output.finish(), RedactionCompletion::Complete)
}

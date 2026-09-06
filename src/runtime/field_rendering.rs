// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Bounded scalar-field rendering shared by text and batch sessions.

use std::fmt::Display;
use std::fmt::Write;

use super::bounded_field_writer::BoundedFieldWriter;
use super::field_render::FieldRender;
use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::RedactionReasons;
use crate::policy::ResolvedField;

struct InputCapture {
    text: String,
    maximum: usize,
    presented: usize,
    overflowed: bool,
}

impl InputCapture {
    fn new(maximum: usize) -> Self {
        Self {
            text: String::new(),
            maximum,
            presented: 0,
            overflowed: false,
        }
    }
}

impl Write for InputCapture {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.presented = self.presented.saturating_add(value.len());
        if value.len() > self.maximum.saturating_sub(self.text.len()) {
            self.overflowed = true;
            return Err(std::fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}

/// Resolves and renders one display field after admitting its key, node, and
/// formatted value through the caller's transaction ledger.
pub(super) fn redact_field_display_for_output<T>(
    policy: &RedactionPolicy,
    field: &str,
    value: &T,
    max_input_bytes: usize,
    max_output_bytes: usize,
) -> FieldRender
where
    T: Display + ?Sized,
{
    let resolved = policy.resolve_field(field);
    if !policy.is_disabled()
        && matches!(
            resolved,
            ResolvedField::Sensitive {
                sensitivity: crate::Sensitivity::High | crate::Sensitivity::Secret
            }
        )
    {
        let sensitivity = match resolved {
            ResolvedField::Sensitive { sensitivity } => sensitivity,
            ResolvedField::PassThrough => unreachable!(),
        };
        let mut writer = BoundedFieldWriter::new(max_output_bytes);
        let result = writer.write_str(policy.masking().mask_opaque(sensitivity));
        if result.is_err() || writer.overflowed() {
            return FieldRender {
                text: String::new(),
                completion: RedactionCompletion::Exhausted,
                reasons: RedactionReasons::empty().with(RedactionReason::OutputLimitReached),
                presented_value_bytes: 0,
                inspected_value_bytes: 0,
            };
        }
        return FieldRender {
            text: writer.finish(),
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty(),
            presented_value_bytes: 0,
            inspected_value_bytes: 0,
        };
    }
    let mut raw = InputCapture::new(max_input_bytes);
    let format_result = Write::write_fmt(&mut raw, format_args!("{value}"));
    let presented = raw.presented;
    if format_result.is_err() {
        return FieldRender {
            text: String::new(),
            completion: RedactionCompletion::Exhausted,
            reasons: RedactionReasons::empty().with(RedactionReason::FormattingFailed),
            presented_value_bytes: presented,
            inspected_value_bytes: raw.text.len(),
        };
    }
    if raw.overflowed {
        return FieldRender {
            text: String::new(),
            completion: RedactionCompletion::Exhausted,
            reasons: RedactionReasons::empty().with(RedactionReason::InputLimitReached),
            presented_value_bytes: presented,
            inspected_value_bytes: raw.text.len(),
        };
    }

    let mut writer = BoundedFieldWriter::new(max_output_bytes);
    let result = if policy.is_disabled() || matches!(resolved, ResolvedField::PassThrough) {
        writer.write_str(&raw.text)
    } else {
        let sensitivity = match resolved {
            ResolvedField::Sensitive { sensitivity } => sensitivity,
            ResolvedField::PassThrough => unreachable!(),
        };
        policy
            .masking()
            .for_level(sensitivity)
            .write_masked(&raw.text, &mut writer)
    };
    if result.is_err() || writer.overflowed() {
        return FieldRender {
            text: String::new(),
            completion: RedactionCompletion::Exhausted,
            reasons: RedactionReasons::empty().with(RedactionReason::OutputLimitReached),
            presented_value_bytes: presented,
            inspected_value_bytes: raw.text.len(),
        };
    }
    FieldRender {
        text: writer.finish(),
        completion: RedactionCompletion::Complete,
        reasons: RedactionReasons::empty(),
        presented_value_bytes: presented,
        inspected_value_bytes: raw.text.len(),
    }
}

/// Resolves and renders one already-owned string field for compatibility with
/// internal callers that do not need display formatting.
#[allow(dead_code)]
pub(super) fn redact_field_text_for_output(
    policy: &RedactionPolicy,
    field: &str,
    value: &str,
    max_output_bytes: usize,
) -> (String, RedactionCompletion) {
    let render = redact_field_display_for_output(policy, field, &value, usize::MAX, max_output_bytes);
    (render.text, render.completion)
}

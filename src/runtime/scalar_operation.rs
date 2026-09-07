// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared scalar admission, formatting, and safe output finalization.

use std::fmt::Display;
use std::fmt::Write;

use super::internal::input_capture::InputCapture;
use super::operation_sink::OperationSink;
use super::rendered_operation::RenderedOperation;
use super::runtime_session::RuntimeSession;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Admits a key before classification and charges only inspected value chunks.
///
/// # Type Parameters
///
/// - `S`: Rendering session sharing transaction resource accounting.
/// - `T`: Possibly unsized value implementing `Display`.
///
/// # Parameters
///
/// - `session`: Active transaction whose output preflight has already passed.
/// - `field`: Raw key, admitted before normalization and policy lookup.
/// - `value`: Scalar formatted only if its policy requires source text.
///
/// # Returns
///
/// An unpublished safe rendering carrying completion and failure provenance.
pub(super) fn redact_field<S, T>(session: &mut S, field: &str, value: &T) -> RenderedOperation
where
    S: RuntimeSession,
    T: Display + ?Sized,
{
    let maximum = session.remaining_output_bytes();
    if !session.admit_format_node(1) {
        let reason = if session.policy().limits().max_depth() == Some(0) {
            RedactionReason::DepthLimitReached
        } else {
            RedactionReason::TraversalLimitReached
        };
        return replacement(maximum, reason);
    }
    if !session.admit_domain_key(field) {
        return replacement(maximum, RedactionReason::TraversalLimitReached);
    }
    if !session.admit_input(field.len()) {
        return replacement(maximum, RedactionReason::InputLimitReached);
    }
    let resolved = session.policy().resolve_field(field);
    let mut sink = OperationSink::new(maximum, "<truncated>", false);
    if !session.policy().is_disabled()
        && let ResolvedField::Sensitive {
            sensitivity: sensitivity @ (Sensitivity::High | Sensitivity::Secret),
        } = resolved
    {
        let _ = sink.write_str(session.policy().masking().mask_opaque(sensitivity));
        return sink.finish_with_reason(RedactionReason::OutputLimitReached);
    }
    let mut capture = InputCapture::new(session.remaining_input_bytes());
    let result = write!(&mut capture, "{value}");
    let (presented, inspected) = capture.usage();
    session.record_input_usage(presented, inspected);
    let raw = match capture.finish(result) {
        Ok(text) => text,
        Err(failure) => return replacement(maximum, failure.reason()),
    };
    match resolved {
        ResolvedField::Sensitive { sensitivity } if !session.policy().is_disabled() => {
            let _ = session
                .policy()
                .masking()
                .for_level(sensitivity)
                .write_masked(&raw, &mut sink);
        }
        _ => {
            let _ = sink.write_str(&raw);
        }
    }
    sink.finish_with_reason(RedactionReason::OutputLimitReached)
}

/// Finalizes a safe replacement without publishing captured raw prefixes.
///
/// # Parameters
///
/// - `maximum`: Remaining final output allowance.
/// - `reason`: Original failure; output exhaustion is added only if necessary.
///
/// # Returns
///
/// A safe marker, or an empty exhausted operation if that marker cannot fit.
#[must_use]
#[inline(always)]
fn replacement(maximum: usize, reason: RedactionReason) -> RenderedOperation {
    OperationSink::new(maximum, "<truncated>", true).finish_with_reason(reason)
}

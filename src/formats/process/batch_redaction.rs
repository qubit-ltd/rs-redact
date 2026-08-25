// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only process-command redaction.

use std::ffi::OsStr;

use super::admitted_command_items::AdmittedCommandItems;
use super::admitted_environment_pairs::AdmittedEnvironmentPairs;
use crate::RedactionReason;
use crate::formats::argv::ArgvItem;
use crate::formats::argv::redaction::redact_heuristically_with_policy;
use crate::formats::env::redaction::redact_os_pairs_with_policy;
use crate::runtime::BatchSession;
use crate::runtime::OperationSink;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts one process command as a batch item.
pub(crate) fn redact_command<'arguments, 'variables, A, E>(
    session: &mut BatchSession,
    program: &'arguments OsStr,
    arguments: A,
    variables: E,
) -> RedactionHandle
where
    A: IntoIterator<Item = ArgvItem<'arguments>>,
    E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
{
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !session.admit_format_node(1) {
        return session.stage_accounted_text(String::new());
    }
    let policy = session.policy().clone();
    let remaining = session.remaining_output_bytes();
    let (argv, command_failed) = {
        let mut command = AdmittedCommandItems {
            session,
            program: Some(ArgvItem::plain(program)),
            arguments: arguments.into_iter(),
            failed: false,
        };
        let output = redact_heuristically_with_policy(&policy, &mut command, remaining);
        (output, command.failed)
    };
    if command_failed || !session.admit_format_node(1) {
        return session.stage_accounted_text(String::new());
    }
    let remaining = remaining.saturating_sub(argv.text().len());
    if remaining == 0 {
        return session.stage_rendered_operation(
            argv.merge(OperationSink::exhausted("", RedactionReason::OutputLimitReached).finish()),
        );
    }
    let (environment, environment_failed) = {
        let mut pairs = AdmittedEnvironmentPairs {
            session,
            variables: variables.into_iter(),
            failed: false,
            marker: std::marker::PhantomData,
        };
        let output = redact_os_pairs_with_policy(&policy, &mut pairs, remaining);
        (output, pairs.failed)
    };
    if environment_failed {
        return session.stage_accounted_text(String::new());
    }
    session.stage_rendered_operation(argv.merge(environment))
}

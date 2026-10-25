// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering sensitivity inspection for environment assignments.

use std::ffi::OsStr;

use super::admission::admit_environment_name;
use crate::Sensitivity;
use crate::policy::ResolvedField;
use crate::runtime::InspectionSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Classifies one UTF-8 assignment and records its sensitivity in the
/// inspection transaction.
///
/// The assignment is subject to the same depth, collection, and input-byte
/// budgets as other inspected format items. If admission fails, inspection
/// stops and the transaction later reports an inconclusive result.
///
/// # Parameters
///
/// - `session`: Transaction that supplies the policy, accounts for inspected
///   input, and accumulates the strongest observed sensitivity.
/// - `name`: UTF-8 environment variable name used for policy classification.
/// - `value`: UTF-8 environment value whose bytes count toward the input
///   budget.
pub(crate) fn inspect_pair(session: &mut InspectionSession, name: &str, value: &str) {
    inspect_os_pairs(session, [(OsStr::new(name), OsStr::new(value))]);
}

/// Classifies borrowed operating-system assignments without rendering their
/// values.
///
/// Pairs are consumed in iterator order. Each admitted pair counts against the
/// transaction's collection, depth, and input-byte budgets. An unrepresentable
/// name is conservatively classified as secret, and inspection stops when a
/// required budget admission fails.
///
/// # Type Parameters
///
/// - `'items`: Borrow lifetime shared by each environment name and value.
/// - `I`: Iterator that yields borrowed operating-system string pairs.
///
/// # Parameters
///
/// - `session`: Transaction that supplies the policy, accounts for inspected
///   input, and accumulates the strongest observed sensitivity.
/// - `pairs`: Environment name and value pairs consumed in iterator order.
pub(crate) fn inspect_os_pairs<'items, I>(session: &mut InspectionSession, pairs: I)
where
    I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
{
    if !session.admit_format_node(1) {
        return;
    }
    let mut pairs = pairs.into_iter();
    loop {
        if pairs.size_hint().1 == Some(0) {
            break;
        }
        if !session.preflight_format_item(2) {
            return;
        }
        let Some((name, value)) = pairs.next() else {
            break;
        };
        if !session.admit_format_collection_item()
            || !session.admit_format_node(2)
            || !admit_environment_name(session, name)
        {
            return;
        }
        if !session.admit_input(
            name.as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len()),
        ) {
            return;
        }
        let sensitivity = match name.to_str() {
            Some(name) => match session.policy().resolve_field(name) {
                ResolvedField::Sensitive { sensitivity } => Some(sensitivity),
                ResolvedField::PassThrough => None,
            },
            None => Some(Sensitivity::Secret),
        };
        if let Some(sensitivity) = sensitivity {
            session.observe_sensitivity(sensitivity);
        }
    }
}

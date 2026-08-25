// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering sensitivity inspection for environment assignments.

use std::ffi::OsStr;

use crate::Sensitivity;
use crate::policy::ResolvedField;
use crate::runtime::InspectionSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Inspects one UTF-8 environment assignment.
pub(crate) fn inspect_pair(session: &mut InspectionSession, name: &str, value: &str) {
    inspect_os_pairs(session, [(OsStr::new(name), OsStr::new(value))]);
}

/// Inspects borrowed operating-system environment assignments.
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
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
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

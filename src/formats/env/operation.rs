// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared admission and rendering operations for environment pairs.

use std::ffi::OsStr;

use super::admission::admit_environment_name;
use super::admission::collect_environment_pairs;
use super::redaction::redact_os_pairs_with_policy;
use super::redaction::redact_pair_with_policy;
use crate::runtime::RenderedOperation;
use crate::runtime::runtime_session::RuntimeSession;

pub(super) fn redact_pair(session: &mut dyn RuntimeSession, name: &str, value: &str) -> Option<RenderedOperation> {
    if !session.admit_format_node(1)
        || !session.admit_format_collection_item()
        || !session.admit_format_node(2)
        || !admit_environment_name(session, OsStr::new(name))
        || !session.admit_input(name.len().saturating_add(value.len()))
    {
        return None;
    }
    Some(redact_pair_with_policy(
        session.policy(),
        name,
        value,
        session.remaining_output_bytes(),
    ))
}

pub(super) fn redact_os_pairs<'items, I>(session: &mut dyn RuntimeSession, pairs: I) -> Option<RenderedOperation>
where
    I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
{
    let pairs = collect_environment_pairs(session, pairs)?;
    Some(redact_os_pairs_with_policy(
        session.policy(),
        pairs,
        session.remaining_output_bytes(),
    ))
}

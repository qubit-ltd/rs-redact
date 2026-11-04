// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
// =============================================================================
//! Shared argv admission and rendering for transaction exits.

use super::ArgvItem;
use super::redaction::redact_heuristically_with_policy;
use super::redaction::redact_items_with_policy;
use crate::runtime::RenderedOperation;
use crate::runtime::collect_flat_format_items;
use crate::runtime::runtime_session::RuntimeSession;

/// Admits and renders argv items without publishing the resulting operation.
///
/// The caller retains responsibility for output exhaustion and for publishing
/// or staging the returned operation in its transaction.
pub(super) fn redact_items<'items, S, I>(
    session: &mut S,
    items: I,
    heuristic: bool,
) -> Option<RenderedOperation>
where
    S: RuntimeSession,
    I: IntoIterator<Item = ArgvItem<'items>>,
{
    let items =
        collect_flat_format_items(session, items, |item| item.value().as_encoded_bytes().len())?;
    Some(if heuristic {
        redact_heuristically_with_policy(session.policy(), items, session.remaining_output_bytes())
    } else {
        redact_items_with_policy(session.policy(), items, session.remaining_output_bytes())
    })
}

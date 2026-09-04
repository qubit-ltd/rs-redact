// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared structural admission for generated Serde redaction.

use std::cell::RefCell;

use super::structured_serde_budget::StructuredSerdeBudget;

thread_local! {
    static STRUCTURED_SERDE_BUDGETS: RefCell<Vec<StructuredSerdeBudget>> = const { RefCell::new(Vec::new()) };
}

/// Hidden scope that shares structural Serde admission across nested derives.
#[doc(hidden)]
pub struct RedactSerializeScope<'policy> {
    /// Policy borrow that keeps the stored address identity valid.
    _policy: &'policy crate::RedactionPolicy,
    /// Whether this guard installed the active root budget.
    owns_budget: bool,
}

impl<'policy> RedactSerializeScope<'policy> {
    /// Starts one policy-scoped structured serialization budget, or joins the
    /// active budget when generated serialization is already nested.
    #[must_use]
    pub fn new(policy: &'policy crate::RedactionPolicy) -> Self {
        let policy_identity = std::ptr::from_ref(policy).addr();
        let owns_budget = STRUCTURED_SERDE_BUDGETS.with(|slot| {
            let mut budgets = slot.borrow_mut();
            if budgets
                .last()
                .is_some_and(|budget| budget.policy_identity == policy_identity)
            {
                return false;
            }
            budgets.push(StructuredSerdeBudget {
                policy_identity,
                policy: *policy.limits(),
                depth: 0,
                nodes: 0,
                collection_items: 0,
                input_bytes: 0,
            });
            true
        });
        Self {
            _policy: policy,
            owns_budget,
        }
    }
}

impl Drop for RedactSerializeScope<'_> {
    fn drop(&mut self) {
        if self.owns_budget {
            STRUCTURED_SERDE_BUDGETS.with(|slot| {
                let _ = slot.borrow_mut().pop();
            });
        }
    }
}

/// Admits one structured node and enters its depth scope.
#[allow(dead_code)]
pub(super) fn admit_node() -> bool {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        let mut budgets = slot.borrow_mut();
        let Some(state) = budgets.last_mut() else {
            return false;
        };
        if state.policy.max_depth().is_some_and(|maximum| state.depth >= maximum)
            || state.policy.max_nodes().is_some_and(|maximum| state.nodes >= maximum)
        {
            return false;
        }
        state.depth += 1;
        state.nodes += 1;
        true
    })
}

/// Leaves the most recently admitted structured node.
#[allow(dead_code)]
pub(super) fn leave_node() {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        if let Some(state) = slot.borrow_mut().last_mut() {
            state.depth = state.depth.saturating_sub(1);
        }
    });
}

/// Admits `count` additional collection items.
pub(super) fn admit_collection_items(count: usize) -> bool {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        let mut budgets = slot.borrow_mut();
        let Some(state) = budgets.last_mut() else {
            return false;
        };
        let next = state.collection_items.saturating_add(count);
        if state
            .policy
            .max_collection_items()
            .is_some_and(|maximum| next > maximum)
        {
            return false;
        }
        state.collection_items = next;
        true
    })
}

/// Admits `bytes` additional source bytes.
#[allow(dead_code)]
pub(super) fn admit_input(bytes: usize) -> bool {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        let mut budgets = slot.borrow_mut();
        let Some(state) = budgets.last_mut() else {
            return false;
        };
        let next = state.input_bytes.saturating_add(bytes);
        if next > state.policy.max_input_bytes() {
            return false;
        }
        state.input_bytes = next;
        true
    })
}

/// Returns the input bytes still available to the active structured serializer.
#[must_use]
pub(super) fn remaining_input_bytes() -> usize {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        let budgets = slot.borrow();
        budgets.last().map_or(0, |state| {
            state.policy.max_input_bytes().saturating_sub(state.input_bytes)
        })
    })
}

/// Runs one generated structured serializer under the shared budget.
///
/// # Errors
///
/// Returns the serializer's error when `body` cannot encode the admitted
/// structure. A rejected root node is serialized as an opaque safe marker.
#[doc(hidden)]
pub fn serialize_structured<S, F>(serializer: S, policy: &crate::RedactionPolicy, body: F) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    F: FnOnce(S) -> Result<S::Ok, S::Error>,
{
    let _scope = RedactSerializeScope::new(policy);
    if !admit_node() {
        return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret).as_ref());
    }
    let result = body(serializer);
    leave_node();
    result
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared structural admission for generated Serde redaction.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::ptr::eq;
use std::ptr::from_ref;
use std::rc::Rc;
use std::sync::Arc;

use serde::Serializer;
use serde::ser::Error;

use super::policy_frame::PolicyFrame;
use super::serde_node_guard::SerdeNodeGuard;
use super::structured_serde_budget::StructuredSerdeBudget;

thread_local! {
    /// Nested transaction ledgers, shared while ordinary serializers remain active.
    static STRUCTURED_SERDE_BUDGETS: RefCell<Vec<StructuredSerdeBudget>> = const { RefCell::new(Vec::new()) };
    /// Owned policy frames preserving snapshot lifetimes during scoped serialization.
    static STRUCTURED_SERDE_POLICIES: RefCell<Vec<PolicyFrame>> = const { RefCell::new(Vec::new()) };
}

/// Thread-affine guard sharing structural Serde admission across nested
/// derives.
///
/// The guard stores an owned policy snapshot in thread-local state. It never
/// stores a raw pointer, so forgetting or moving a caller's policy cannot make
/// [`current_policy`] dangle. Generated projections and scoped adapters use
/// this guard to restore the previous policy and budget on return or unwinding.
///
/// # Type Parameters
///
/// - `'policy`: Borrow that keeps the source policy alive until this guard
///   drops.
#[doc(hidden)]
pub struct RedactSerializeScope<'policy> {
    /// Keeps the guard tied to the caller's policy lifetime.
    _policy: PhantomData<&'policy crate::RedactionPolicy>,
    /// Makes the guard thread-affine because it mutates thread-local state.
    _not_send: PhantomData<Rc<()>>,
    /// Whether this guard installed the active root budget.
    owns_budget: bool,
}

impl<'policy> RedactSerializeScope<'policy> {
    /// Starts one policy-scoped structured serialization budget, or joins the
    /// active budget when generated serialization is already nested.
    /// Source addresses are only a reuse hint: the owned snapshot must still
    /// equal the supplied policy, because a forgotten guard permits the caller
    /// to replace its policy at the same address.
    ///
    /// # Parameters
    ///
    /// - `policy`: Policy whose owned snapshot is installed until this guard
    ///   drops.
    ///
    /// # Returns
    ///
    /// A thread-affine guard joining the active matching budget, or owning a
    /// new root budget when the policy changes outside an ordinary serializer.
    #[must_use]
    pub fn new(policy: &'policy crate::RedactionPolicy) -> Self {
        let source_identity = from_ref(policy).addr();
        let snapshot = STRUCTURED_SERDE_POLICIES
            .with(|slot| {
                slot.borrow()
                    .last()
                    .filter(|frame| {
                        eq(frame.snapshot.as_ref(), policy)
                            || (frame.source_identity == source_identity && frame.snapshot.as_ref() == policy)
                    })
                    .map(|frame| Arc::clone(&frame.snapshot))
            })
            .unwrap_or_else(|| Arc::new(policy.clone()));
        let policy_identity = Arc::as_ptr(&snapshot).addr();
        let owns_budget = STRUCTURED_SERDE_BUDGETS.with(|slot| {
            let mut budgets = slot.borrow_mut();
            if budgets
                .last()
                .is_some_and(|budget| budget.policy_identity == policy_identity || budget.raw_serializers > 0)
            {
                return false;
            }
            budgets.push(StructuredSerdeBudget {
                policy_identity,
                policy: *policy.limits(),
                raw_serializers: 0,
                depth: 0,
                nodes: 0,
                collection_items: 0,
                input_bytes: 0,
                payload_bytes: 0,
            });
            true
        });
        STRUCTURED_SERDE_POLICIES.with(|slot| {
            slot.borrow_mut().push(PolicyFrame {
                source_identity,
                snapshot,
            })
        });
        Self {
            _policy: PhantomData,
            _not_send: PhantomData,
            owns_budget,
        }
    }
}

impl Drop for RedactSerializeScope<'_> {
    /// Pops this policy frame and releases its owned root ledger, if any.
    fn drop(&mut self) {
        if self.owns_budget {
            STRUCTURED_SERDE_BUDGETS.with(|slot| {
                let _ = slot.borrow_mut().pop();
            });
        }
        STRUCTURED_SERDE_POLICIES.with(|slot| {
            let _ = slot.borrow_mut().pop();
        });
    }
}

/// Returns `Some` with the owned policy snapshot of the active scope.
///
/// Returns `None` when no structured serialization scope is active.
///
/// # Returns
///
/// Some owned snapshot for the innermost active scope; None outside scoped
/// structured serialization. The snapshot remains valid after the guard drops.
#[doc(hidden)]
#[must_use]
#[inline(always)]
pub fn current_policy() -> Option<Arc<crate::RedactionPolicy>> {
    STRUCTURED_SERDE_POLICIES.with(|slot| slot.borrow().last().map(|frame| Arc::clone(&frame.snapshot)))
}

/// Admits one structured node and enters its depth scope.
///
/// # Returns
///
/// True after charging one node and entering its depth; false if no scope
/// is active or a structural limit rejects entry. Only success needs a leave.
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

/// Checks the raw UTF-8 length of a key against the active Serde budget.
///
/// # Errors
///
/// Returns a value-free serializer error when the key exceeds its limit or
/// no redaction scope is active. This check precedes key lookup and output.
///
/// # Type Parameters
///
/// - `E`: Serializer error type used for a value-free failure.
///
/// # Parameters
///
/// - `key`: Raw key checked before normalization or serialization.
///
/// # Returns
///
/// Success when an active scope admits the raw key length; no budget is
/// charged.
pub(super) fn check_key_bytes<E: Error>(key: &str) -> Result<(), E> {
    let admitted = STRUCTURED_SERDE_BUDGETS.with(|slot| {
        slot.borrow()
            .last()
            .is_some_and(|state| state.policy.max_key_bytes().is_none_or(|maximum| key.len() <= maximum))
    });
    if admitted {
        Ok(())
    } else {
        Err(E::custom("redaction key byte budget exceeded"))
    }
}

/// Admits `count` additional collection items.
///
/// # Parameters
///
/// - `count`: Additional collection entries to reserve.
///
/// # Returns
///
/// True if the cumulative count was admitted; false without changing the
/// counter when no scope is active or its item limit rejects the count.
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
///
/// # Parameters
///
/// - `bytes`: Additional raw scalar bytes to reserve.
///
/// # Returns
///
/// True after charging the bytes; false without changing the counter when
/// no scope is active or the cumulative input limit rejects the bytes.
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
///
/// # Returns
///
/// Remaining admitted input capacity, or zero when no scope is active.
#[must_use]
#[inline(always)]
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
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
/// - `F`: One-shot callback returning the destination result.
///
/// # Parameters
///
/// - `serializer`: Destination receiving the admitted root or a safe marker.
/// - `policy`: Immutable snapshot installed for the callback.
/// - `body`: Called once only after root structural admission.
///
/// # Returns
///
/// The downstream result after the admitted representation is serialized.
#[doc(hidden)]
pub fn serialize_structured<S, F>(serializer: S, policy: &crate::RedactionPolicy, body: F) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    F: FnOnce(S) -> Result<S::Ok, S::Error>,
{
    let _scope = RedactSerializeScope::new(policy);
    if !admit_node() {
        return serialize_payload(serializer, policy.masking().mask_opaque(crate::Sensitivity::Secret));
    }
    let _node = SerdeNodeGuard;
    body(serializer)
}

/// Charges scalar payload bytes, excluding format-specific escaping and
/// framing. Returns false without changing the counter when the shared limit is
/// exceeded.
///
/// # Parameters
///
/// - `bytes`: Logical scalar bytes, excluding encoder escaping and framing.
///
/// # Returns
///
/// True after charging payload; false without changing the counter if no
/// scope is active, addition overflows, or the payload limit would be exceeded.
pub(super) fn admit_payload(bytes: usize) -> bool {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        let mut budgets = slot.borrow_mut();
        let Some(state) = budgets.last_mut() else {
            return false;
        };
        let Some(next) = state.payload_bytes.checked_add(bytes) else {
            return false;
        };
        if next > state.policy.max_serde_payload_bytes() {
            return false;
        }
        state.payload_bytes = next;
        true
    })
}

/// Serializes a string payload after cumulative payload admission.
///
/// # Errors
///
/// Returns a Serde error when the payload exceeds the shared allowance, or
/// propagates the downstream string serialization error.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
///
/// # Parameters
///
/// - `serializer`: Destination receiving the admitted string.
/// - `value`: Transformed string counted once as logical scalar payload.
///
/// # Returns
///
/// The downstream result after the admitted representation is serialized.
pub(super) fn serialize_payload<S: Serializer>(serializer: S, value: &str) -> Result<S::Ok, S::Error> {
    if !admit_payload(value.len()) {
        return Err(Error::custom("redaction scalar payload budget exceeded"));
    }
    serializer.serialize_str(value)
}

/// Returns the logical scalar payload capacity left in the active scope.
///
/// # Returns
///
/// Remaining logical scalar capacity, or zero when no scope is active.
#[must_use]
#[inline(always)]
pub(super) fn remaining_payload_bytes() -> usize {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        slot.borrow().last().map_or(0, |state| {
            state
                .policy
                .max_serde_payload_bytes()
                .saturating_sub(state.payload_bytes)
        })
    })
}

/// Pins the caller's budget while an ordinary serializer may enter another
/// policy. Returns false when no structured operation is active.
///
/// # Returns
///
/// True after pinning the current budget; false when no budget is active.
/// Each successful entry requires exactly one matching leave.
pub(super) fn enter_raw_serializer() -> bool {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        let mut budgets = slot.borrow_mut();
        let Some(state) = budgets.last_mut() else {
            return false;
        };
        state.raw_serializers += 1;
        true
    })
}

/// Releases a raw serializer's budget pin during normal return or unwinding.
///
/// # Panics
///
/// In debug builds, panics if called with an active budget but without a
/// matching successful raw-serializer entry.
pub(super) fn leave_raw_serializer() {
    STRUCTURED_SERDE_BUDGETS.with(|slot| {
        if let Some(state) = slot.borrow_mut().last_mut() {
            state.raw_serializers -= 1;
        }
    });
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared accounting capabilities implemented by every transaction mode.

use std::mem::take;

#[cfg(feature = "json")]
use qubit_budget::json::JsonValueBudget;
#[cfg(feature = "json")]
use serde_json::Value;

#[cfg(feature = "json")]
use super::rendered_operation::RenderedOperation;
#[cfg(feature = "json")]
use super::rendered_summary::rendered_summary;
use super::runtime_core::RuntimeCore;
use super::transaction_phase::TransactionPhase;
use crate::RedactionPolicy;
#[cfg(any(feature = "json", feature = "http", feature = "uri"))]
use crate::RedactionReason;
use crate::RedactionSummary;
use crate::Sensitivity;
use crate::policy::ResolvedField;

/// Exposes publication-independent transaction accounting to format writers.
pub(crate) trait RuntimeSession {
    /// Returns the immutable shared accounting core.
    ///
    /// # Returns
    ///
    /// The shared accounting core borrowed for observation.
    #[must_use]
    fn runtime(&self) -> &RuntimeCore;

    /// Returns the mutable shared accounting core.
    ///
    /// # Returns
    ///
    /// The shared accounting core borrowed for state changes.
    #[must_use]
    fn runtime_mut(&mut self) -> &mut RuntimeCore;

    /// Reports whether this session performs inspection without rendering.
    ///
    /// # Returns
    ///
    /// Whether this transaction observes sensitivity without rendering text.
    #[must_use]
    fn is_inspection(&self) -> bool;

    /// Records one policy-resolved sensitivity for inspection.
    ///
    /// # Parameters
    ///
    /// - `sensitivity`: Newly observed policy classification.
    fn observe_sensitivity(&mut self, sensitivity: Sensitivity);

    /// Returns the immutable policy snapshot.
    ///
    /// # Returns
    ///
    /// The immutable policy snapshot retained by this transaction.
    #[must_use]
    #[inline(always)]
    fn policy(&self) -> &RedactionPolicy {
        self.runtime().policy()
    }

    /// Starts per-item accounting unless an outer operation owns the scope.
    ///
    /// # Returns
    ///
    /// `true` if this call owns a newly created item scope; `false` when an
    /// outer operation already owns it. Only the owner may close the scope.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if internal summary and usage scope ownership
    /// disagree while creating an item scope.
    #[must_use]
    #[inline(always)]
    fn begin_item_summary(&mut self) -> bool {
        self.runtime_mut().begin_item_summary()
    }

    /// Ends per-item accounting when the caller created the active scope.
    ///
    /// # Parameters
    ///
    /// - `owns_item_summary`: Ownership returned by `begin_item_summary`.
    #[inline(always)]
    fn end_item_summary(&mut self, owns_item_summary: bool) {
        self.runtime_mut().end_item_summary(owns_item_summary);
    }

    /// Merges one accounting delta into transaction and active item summaries.
    ///
    /// # Parameters
    ///
    /// - `delta`: Observed completion and reason facts to merge.
    #[inline(always)]
    fn record_summary(&mut self, delta: RedactionSummary) {
        self.runtime_mut().record_summary(delta);
    }

    /// Adds retained output bytes to transaction and active item accounting.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Newly retained final escaped bytes.
    #[inline(always)]
    fn record_output_bytes(&mut self, bytes: usize) {
        self.runtime_mut().record_output_bytes(bytes);
    }

    /// Starts one structured domain value.
    ///
    /// # Returns
    ///
    /// Whether a node was admitted and its nesting scope entered. Call
    /// `leave_domain_value` only after successful entry.
    #[must_use]
    #[inline(always)]
    fn begin_domain_value(&mut self) -> bool {
        self.runtime_mut().begin_domain_value()
    }

    /// Charges one domain field before its value is accessed.
    ///
    /// # Returns
    ///
    /// Whether one field node was charged before value access.
    #[must_use]
    #[inline(always)]
    fn admit_domain_field(&mut self) -> bool {
        self.runtime_mut().admit_domain_field()
    }

    /// Charges one collection item before its iterator advances.
    ///
    /// # Returns
    ///
    /// Whether one cumulative collection item was charged before value access.
    #[must_use]
    #[inline(always)]
    fn admit_domain_collection_item(&mut self) -> bool {
        self.runtime_mut().admit_domain_collection_item()
    }

    /// Checks one raw domain key before lookup, rendering, or value access.
    ///
    /// Returns whether the key fits the active per-key byte limit.
    ///
    /// # Parameters
    ///
    /// - `key`: Raw UTF-8 key checked before normalization or value access.
    ///
    /// # Returns
    ///
    /// Whether the key fits and structural traversal remains open.
    #[must_use]
    #[inline(always)]
    fn admit_domain_key(&mut self, key: &str) -> bool {
        self.runtime_mut().admit_domain_key(key)
    }

    /// Admits one format node through the shared structural ledger.
    ///
    /// # Parameters
    ///
    /// - `depth`: Root-inclusive format depth, starting at one.
    ///
    /// # Returns
    ///
    /// Whether the node was charged; rejection records its depth or traversal
    /// cause.
    #[must_use]
    #[inline(always)]
    fn admit_format_node(&mut self, depth: usize) -> bool {
        self.runtime_mut().admit_format_node(depth)
    }

    /// Admits one format collection item through the shared ledger.
    ///
    /// # Returns
    ///
    /// Whether a cumulative collection item was admitted and charged.
    #[must_use]
    #[inline(always)]
    fn admit_format_collection_item(&mut self) -> bool {
        self.admit_domain_collection_item()
    }

    /// Checks structural capacity before advancing an untrusted iterator.
    ///
    /// # Parameters
    ///
    /// - `depth`: Root-inclusive depth of the next format item.
    ///
    /// # Returns
    ///
    /// Whether both collection and node capacity permit advancing the iterator;
    /// this preflight does not charge the item itself.
    #[must_use]
    #[inline(always)]
    fn preflight_format_item(&mut self, depth: usize) -> bool {
        self.runtime_mut().preflight_format_item(depth)
    }

    /// Checks collection capacity before advancing an untrusted iterator.
    ///
    /// # Returns
    ///
    /// Whether collection capacity permits advancing the iterator; the caller
    /// must subsequently charge any yielded item.
    #[must_use]
    #[inline(always)]
    fn preflight_collection_item(&mut self) -> bool {
        self.runtime_mut().preflight_collection_item()
    }

    /// Admits a borrowed JSON value through the shared JSON ledger.
    ///
    /// # Parameters
    ///
    /// - `value`: Parsed tree to account before it is rendered.
    ///
    /// # Returns
    ///
    /// Whether the entire tree fits the shared JSON-specific limits.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    fn admit_json_value(&mut self, value: &Value) -> bool {
        self.runtime_mut().admit_json_value(value)
    }

    /// Splits JSON structure accounting from lexical value accounting.
    ///
    /// # Returns
    ///
    /// Disjoint structural-accounting capability and lexical JSON value budget.
    #[cfg(feature = "json")]
    #[inline(always)]
    #[must_use]
    fn split_json_admission(&mut self) -> (super::JsonStructureAdmission<'_>, &mut JsonValueBudget) {
        self.runtime_mut().split_json_admission()
    }

    /// Records rejection by the transaction-wide JSON value budget.
    #[cfg(feature = "json")]
    #[inline(always)]
    fn record_json_value_limit_reached(&mut self) {
        self.runtime_mut().record_json_value_limit_reached();
    }

    /// Releases one active domain-value depth.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if there is no successfully entered domain scope
    /// to leave. Every successful entry must have exactly one matching leave.
    #[inline(always)]
    fn leave_domain_value(&mut self) {
        self.runtime_mut().leave_domain_value();
    }

    /// Reports whether the active domain frame has stopped writing.
    ///
    /// # Returns
    ///
    /// Whether the current domain frame has stopped accepting content.
    #[must_use]
    #[inline(always)]
    fn domain_frame_is_truncated(&self) -> bool {
        self.runtime().domain_frame_truncated
    }

    /// Marks an inspection inconclusive for one machine-readable cause.
    ///
    /// # Parameters
    ///
    /// - `reason`: Cause preventing a conclusive inspection.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if called on a rendering session.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[inline]
    fn fail_inspection(&mut self, reason: RedactionReason) {
        debug_assert!(self.is_inspection());
        self.record_summary(RedactionSummary::truncated(reason));
    }

    /// Classifies one named scalar field without rendering its value.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw field name used for classification.
    /// - `value`: Raw field value whose byte length participates in input
    ///   admission.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if called on a rendering session.
    fn inspect_field(&mut self, field: &str, value: &str) {
        debug_assert!(self.is_inspection());
        if !self.admit_input(field.len().saturating_add(value.len())) {
            return;
        }
        if let ResolvedField::Sensitive { sensitivity } = self.policy().resolve_field(field) {
            self.observe_sensitivity(sensitivity);
        }
    }

    /// Returns output capacity still available to the active domain frame.
    ///
    /// # Returns
    ///
    /// Escaped bytes still available within this frame; inspection returns
    /// `usize::MAX` because it does not construct an output frame.
    #[must_use]
    #[inline(always)]
    fn remaining_domain_frame_output_bytes(&self) -> usize {
        if self.is_inspection() {
            return usize::MAX;
        }
        self.remaining_output_bytes()
            .saturating_sub(self.runtime().domain_frame_output_bytes)
    }

    /// Appends one complete fragment to the transaction-owned domain frame.
    ///
    /// # Parameters
    ///
    /// - `text`: Fragment already checked against the frame's escaped-byte
    ///   allowance.
    fn append_domain_frame_fragment(&mut self, text: &str) {
        if self.is_inspection() {
            return;
        }
        for character in text.chars() {
            self.runtime_mut().domain_frame.push(character);
            self.runtime_mut().domain_frame_output_bytes += encoded_log_safe_len(character);
        }
    }

    /// Appends a fragment while enforcing the shared output limit.
    ///
    /// # Parameters
    ///
    /// - `text`: Raw fragment escaped and charged one Unicode scalar at a time.
    ///
    /// # Returns
    ///
    /// Whether the full fragment was appended; rejection closes the frame and
    /// retains a safe fallback according to its remaining output capacity.
    fn write_domain_fragment(&mut self, text: &str) -> bool {
        if self.runtime().domain_frame_truncated {
            return false;
        }
        if self.is_inspection() {
            return true;
        }
        for character in text.chars() {
            if encoded_log_safe_len(character) > self.remaining_domain_frame_output_bytes() {
                self.mark_domain_frame_output_limit_reached();
                self.truncate_domain_frame_without_output_limit();
                return false;
            }
            self.runtime_mut().domain_frame.push(character);
            self.runtime_mut().domain_frame_output_bytes += encoded_log_safe_len(character);
        }
        true
    }

    /// Marks the active domain frame as having reached the output limit.
    #[inline(always)]
    fn mark_domain_frame_output_limit_reached(&mut self) {
        self.runtime_mut().domain_frame_output_limit_reached = true;
    }

    /// Marks the active domain frame as closed to later field access.
    #[inline(always)]
    fn mark_domain_frame_truncated(&mut self) {
        self.runtime_mut().domain_frame_truncated = true;
    }

    /// Removes raw characters until the encoded frame fits `limit` bytes.
    ///
    /// # Parameters
    ///
    /// - `limit`: Maximum retained escaped bytes after removing complete
    ///   characters.
    fn truncate_domain_frame_to(&mut self, limit: usize) {
        while self.runtime().domain_frame_output_bytes > limit {
            let Some(character) = self.runtime_mut().domain_frame.pop() else {
                self.runtime_mut().domain_frame_output_bytes = 0;
                return;
            };
            self.runtime_mut().domain_frame_output_bytes = self
                .runtime()
                .domain_frame_output_bytes
                .saturating_sub(encoded_log_safe_len(character));
        }
    }

    /// Appends the standard marker after structural or input truncation.
    fn truncate_domain_frame_without_output_limit(&mut self) {
        if self.runtime().domain_frame_truncated {
            return;
        }
        if self.is_inspection() {
            self.mark_domain_frame_truncated();
            return;
        }
        const MARKER: &str = "<truncated>";
        if MARKER.len() > self.remaining_output_bytes() {
            self.truncate_domain_frame_to(0);
            self.mark_domain_frame_output_limit_reached();
            self.runtime_mut().phase = TransactionPhase::OutputExhausted;
        } else {
            let limit = self.remaining_output_bytes().saturating_sub(MARKER.len());
            self.truncate_domain_frame_to(limit);
            self.append_domain_frame_fragment(MARKER);
        }
        self.mark_domain_frame_truncated();
    }

    /// Removes a final separator from the transaction-owned domain frame.
    fn trim_domain_frame_separator(&mut self) {
        if self.is_inspection() {
            return;
        }
        if self.runtime().domain_frame.ends_with(", ") {
            let length = self.runtime().domain_frame.len();
            self.runtime_mut().domain_frame.truncate(length - 2);
            self.runtime_mut().domain_frame_output_bytes = self.runtime().domain_frame_output_bytes.saturating_sub(2);
        }
    }

    /// Takes the completed domain frame and resets its local state.
    ///
    /// # Returns
    ///
    /// Owned raw frame text, omission flag, and output-limit flag, in that
    /// order. All local frame state is reset; callers retain shared
    /// transaction accounting.
    #[must_use]
    #[inline]
    fn finish_domain_frame(&mut self) -> (String, bool, bool) {
        let output = take(&mut self.runtime_mut().domain_frame);
        let truncated = take(&mut self.runtime_mut().domain_frame_truncated);
        let output_limit_reached = take(&mut self.runtime_mut().domain_frame_output_limit_reached);
        self.runtime_mut().domain_frame_output_bytes = 0;
        (output, truncated, output_limit_reached)
    }

    /// Records provenance for a format result embedded in a domain writer.
    ///
    /// # Parameters
    ///
    /// - `operation`: Unpublished rendering whose completion facts belong to
    ///   this frame.
    #[cfg(feature = "json")]
    #[inline]
    fn record_rendered_provenance(&mut self, operation: &RenderedOperation) {
        let summary = rendered_summary(operation.completion(), operation.reasons());
        self.record_summary(summary);
    }

    /// Reports whether the transaction exhausted its output budget.
    ///
    /// # Returns
    ///
    /// Whether no later rendering operation may inspect input or emit output.
    #[must_use]
    #[inline(always)]
    fn is_output_exhausted(&self) -> bool {
        !self.is_inspection() && self.runtime().is_output_exhausted()
    }

    /// Stops an operation before it observes input after output exhaustion.
    ///
    /// # Returns
    ///
    /// Whether the caller must skip this operation. A skipped rendering records
    /// output exhaustion without inspecting additional input.
    #[must_use]
    #[inline(always)]
    fn skip_aggregate_for_exhausted_output(&mut self) -> bool {
        !self.is_inspection() && self.runtime_mut().skip_aggregate_for_exhausted_output()
    }

    /// Returns output capacity still available to one renderer.
    ///
    /// # Returns
    ///
    /// Remaining final escaped-output bytes; inspection sessions use an
    /// unbounded sentinel because they produce no text.
    #[must_use]
    #[inline(always)]
    fn remaining_output_bytes(&self) -> usize {
        if self.is_inspection() {
            usize::MAX
        } else {
            self.runtime().remaining_output_bytes()
        }
    }

    /// Returns input capacity not yet inspected by this transaction.
    ///
    /// # Returns
    ///
    /// Remaining admitted input capacity; the inspection adapter reports an
    /// unbounded sentinel here but still enforces input through admission
    /// methods.
    #[must_use]
    #[inline(always)]
    fn remaining_input_bytes(&self) -> usize {
        if self.is_inspection() {
            usize::MAX
        } else {
            self.runtime().remaining_input_bytes()
        }
    }

    /// Admits encoded input before any parser or renderer observes it.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Size of the complete raw input unit submitted for admission.
    ///
    /// # Returns
    ///
    /// Whether the whole unit was admitted. Rejected units count as presented
    /// but contribute no inspected bytes.
    #[inline(always)]
    fn admit_input(&mut self, bytes: usize) -> bool {
        self.runtime_mut().admit_input(bytes)
    }

    /// Records the measured input of a bounded scalar formatter.
    ///
    /// # Parameters
    ///
    /// - `presented`: Bytes submitted by the bounded formatter.
    /// - `inspected`: Accepted bytes, including bytes discarded after formatter
    ///   failure.
    #[inline(always)]
    fn record_input_usage(&mut self, presented: usize, inspected: usize) {
        self.runtime_mut().record_input_usage(presented, inspected);
    }

    /// Admits the UTF-8 prefix that fits the shared input budget.
    ///
    /// # Parameters
    ///
    /// - `text`: Raw UTF-8 text whose complete length is presented.
    ///
    /// # Returns
    ///
    /// The longest valid UTF-8 prefix within the remaining input allowance.
    ///
    /// # Type Parameters
    ///
    /// - `'text`: Borrow of the input retained by the returned prefix.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[must_use]
    #[inline(always)]
    fn admit_input_prefix<'text>(&mut self, text: &'text str) -> &'text str {
        self.runtime_mut().admit_input_prefix(text)
    }

    /// Admits a captured source whose complete length may be unknown.
    ///
    /// # Parameters
    ///
    /// - `total`: `Some(length)` is the complete source length; `None` means
    ///   unknown.
    /// - `inspectable`: Captured bytes available for whole-unit admission.
    ///
    /// # Returns
    ///
    /// Whether the complete captured unit was admitted; omitted source
    /// accounting retains the distinction between a known count and unknown
    /// length.
    #[cfg(feature = "http")]
    #[inline(always)]
    fn admit_source_input(&mut self, total: Option<usize>, inspectable: usize) -> bool {
        self.runtime_mut().admit_source_input(total, inspectable)
    }
}

/// Returns the final log-safe byte count of one source character.
///
/// # Parameters
///
/// - `character`: Source Unicode scalar to measure.
///
/// # Returns
///
/// Its final encoded byte length under the common log-control escape rules.
#[must_use]
#[inline]
fn encoded_log_safe_len(character: char) -> usize {
    let mut buffer = [0_u8; 12];
    crate::output::log_escape::encode_log_safe_character(character, &mut buffer)
        .map_or(character.len_utf8(), |encoded| encoded.len())
}

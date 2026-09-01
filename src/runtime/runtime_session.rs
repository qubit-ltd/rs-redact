// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared accounting capabilities implemented by every transaction mode.

#[cfg(feature = "json")]
use qubit_budget::json::JsonValueBudget;

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
    fn runtime(&self) -> &RuntimeCore;

    /// Returns the mutable shared accounting core.
    fn runtime_mut(&mut self) -> &mut RuntimeCore;

    /// Reports whether this session performs inspection without rendering.
    fn is_inspection(&self) -> bool;

    /// Records one policy-resolved sensitivity for inspection.
    fn observe_sensitivity(&mut self, sensitivity: Sensitivity);

    /// Returns the immutable policy snapshot.
    #[must_use]
    #[inline(always)]
    fn policy(&self) -> &RedactionPolicy {
        self.runtime().policy()
    }

    /// Starts per-item accounting unless an outer operation owns the scope.
    #[must_use]
    fn begin_item_summary(&mut self) -> bool {
        self.runtime_mut().begin_item_summary()
    }

    /// Ends per-item accounting when the caller created the active scope.
    fn end_item_summary(&mut self, owns_item_summary: bool) {
        self.runtime_mut().end_item_summary(owns_item_summary);
    }

    /// Merges one accounting delta into transaction and active item summaries.
    fn record_summary(&mut self, delta: RedactionSummary) {
        self.runtime_mut().record_summary(delta);
    }

    /// Adds retained output bytes to transaction and active item accounting.
    fn record_output_bytes(&mut self, bytes: usize) {
        self.runtime_mut().record_output_bytes(bytes);
    }

    /// Starts one structured domain value.
    #[must_use]
    fn begin_domain_value(&mut self) -> bool {
        self.runtime_mut().begin_domain_value()
    }

    /// Charges one domain field before its value is accessed.
    #[must_use]
    #[inline(always)]
    fn admit_domain_field(&mut self) -> bool {
        self.runtime_mut().admit_domain_field()
    }

    /// Charges one collection item before its iterator advances.
    #[must_use]
    #[inline(always)]
    fn admit_domain_collection_item(&mut self) -> bool {
        self.runtime_mut().admit_domain_collection_item()
    }

    /// Admits one format node through the shared structural ledger.
    #[must_use]
    fn admit_format_node(&mut self, depth: usize) -> bool {
        self.runtime_mut().admit_format_node(depth)
    }

    /// Admits one format collection item through the shared ledger.
    #[must_use]
    #[inline(always)]
    fn admit_format_collection_item(&mut self) -> bool {
        self.admit_domain_collection_item()
    }

    /// Checks structural capacity before advancing an untrusted iterator.
    #[must_use]
    #[inline(always)]
    fn preflight_format_item(&mut self, depth: usize) -> bool {
        self.runtime_mut().preflight_format_item(depth)
    }

    /// Checks collection capacity before advancing an untrusted iterator.
    #[must_use]
    #[inline(always)]
    fn preflight_collection_item(&mut self) -> bool {
        self.runtime_mut().preflight_collection_item()
    }

    /// Admits a borrowed JSON value through the shared JSON ledger.
    #[cfg(feature = "json")]
    #[must_use]
    fn admit_json_value(&mut self, value: &serde_json::Value) -> bool {
        self.runtime_mut().admit_json_value(value)
    }

    /// Splits JSON structure accounting from lexical value accounting.
    #[cfg(feature = "json")]
    fn split_json_admission(
        &mut self,
    ) -> (super::JsonStructureAdmission<'_>, &mut JsonValueBudget) {
        self.runtime_mut().split_json_admission()
    }

    /// Records rejection by the transaction-wide JSON value budget.
    #[cfg(feature = "json")]
    fn record_json_value_limit_reached(&mut self) {
        self.runtime_mut().record_json_value_limit_reached();
    }

    /// Releases one active domain-value depth.
    #[inline(always)]
    fn leave_domain_value(&mut self) {
        self.runtime_mut().leave_domain_value();
    }

    /// Reports whether the active domain frame has stopped writing.
    #[must_use]
    #[inline(always)]
    fn domain_frame_is_truncated(&self) -> bool {
        self.runtime().domain_frame_truncated
    }

    /// Marks an inspection inconclusive for one machine-readable cause.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    fn fail_inspection(&mut self, reason: RedactionReason) {
        debug_assert!(self.is_inspection());
        self.record_summary(RedactionSummary::truncated(reason));
    }

    /// Classifies one named scalar field without rendering its value.
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
    fn mark_domain_frame_output_limit_reached(&mut self) {
        self.runtime_mut().domain_frame_output_limit_reached = true;
    }

    /// Marks the active domain frame as closed to later field access.
    fn mark_domain_frame_truncated(&mut self) {
        self.runtime_mut().domain_frame_truncated = true;
    }

    /// Removes raw characters until the encoded frame fits `limit` bytes.
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
            self.runtime_mut().domain_frame_output_bytes =
                self.runtime().domain_frame_output_bytes.saturating_sub(2);
        }
    }

    /// Takes the completed domain frame and resets its local state.
    #[must_use]
    fn finish_domain_frame(&mut self) -> (String, bool, bool) {
        let output = std::mem::take(&mut self.runtime_mut().domain_frame);
        let truncated = std::mem::take(&mut self.runtime_mut().domain_frame_truncated);
        let output_limit_reached =
            std::mem::take(&mut self.runtime_mut().domain_frame_output_limit_reached);
        self.runtime_mut().domain_frame_output_bytes = 0;
        (output, truncated, output_limit_reached)
    }

    /// Records provenance for a format result embedded in a domain writer.
    #[cfg(feature = "json")]
    fn record_rendered_provenance(&mut self, operation: &RenderedOperation) {
        let summary = rendered_summary(operation.completion(), operation.reasons());
        self.record_summary(summary);
    }

    /// Reports whether the transaction exhausted its output budget.
    #[must_use]
    #[inline(always)]
    fn is_output_exhausted(&self) -> bool {
        !self.is_inspection() && self.runtime().is_output_exhausted()
    }

    /// Stops an operation before it observes input after output exhaustion.
    #[must_use]
    #[inline(always)]
    fn skip_aggregate_for_exhausted_output(&mut self) -> bool {
        !self.is_inspection() && self.runtime_mut().skip_aggregate_for_exhausted_output()
    }

    /// Returns output capacity still available to one renderer.
    #[must_use]
    #[inline(always)]
    fn remaining_output_bytes(&self) -> usize {
        if self.is_inspection() {
            usize::MAX
        } else {
            self.runtime().remaining_output_bytes()
        }
    }

    /// Admits encoded input before any parser or renderer observes it.
    fn admit_input(&mut self, bytes: usize) -> bool {
        self.runtime_mut().admit_input(bytes)
    }

    /// Admits the UTF-8 prefix that fits the shared input budget.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[must_use]
    fn admit_input_prefix<'text>(&mut self, text: &'text str) -> &'text str {
        self.runtime_mut().admit_input_prefix(text)
    }

    /// Admits a captured source whose complete length may be unknown.
    #[cfg(feature = "http")]
    fn admit_source_input(&mut self, total: Option<usize>, inspectable: usize) -> bool {
        self.runtime_mut().admit_source_input(total, inspectable)
    }
}

/// Returns the final log-safe byte count of one source character.
#[must_use]
fn encoded_log_safe_len(character: char) -> usize {
    let mut buffer = [0_u8; 12];
    crate::output::log_escape::encode_log_safe_character(character, &mut buffer)
        .map_or(character.len_utf8(), |encoded| encoded.len())
}

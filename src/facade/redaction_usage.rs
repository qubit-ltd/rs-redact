// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Resource accounting for one redaction transaction.

/// Measured resource use for one redaction transaction.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::standard().redact_field("id", "42");
/// assert_eq!(output.summary().usage().inspected_input_bytes(), 4);
/// assert_eq!(output.summary().usage().output_bytes(), 2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionUsage {
    /// Bytes presented at public input boundaries.
    presented_input_bytes: usize,
    /// Presented bytes admitted for inspection.
    inspected_input_bytes: usize,
    /// Escaped bytes retained in final output.
    output_bytes: usize,
    /// Structural nodes admitted during traversal.
    visited_nodes: usize,
    /// Sequence and map items admitted during traversal.
    visited_collection_items: usize,
    /// Greatest active structural depth observed.
    max_depth: usize,
    /// Known bytes omitted at admission boundaries.
    omitted_input_bytes: Option<usize>,
}

impl Default for RedactionUsage {
    /// Creates the empty resource measurement used by a fresh transaction.
    ///
    /// # Returns
    ///
    /// An empty measurement with all counters zero and known zero omissions.
    #[inline(always)]
    fn default() -> Self {
        Self::empty()
    }
}

impl RedactionUsage {
    /// Creates an empty measurement for a newly started transaction.
    ///
    /// # Returns
    ///
    /// An empty measurement with all counters zero and known zero omissions.
    #[must_use]
    #[inline(always)]
    pub const fn empty() -> Self {
        Self {
            presented_input_bytes: 0,
            inspected_input_bytes: 0,
            output_bytes: 0,
            visited_nodes: 0,
            visited_collection_items: 0,
            max_depth: 0,
            omitted_input_bytes: Some(0),
        }
    }

    /// Returns the bytes supplied by callers before input admission.
    ///
    /// # Returns
    ///
    /// Bytes presented at admitted or rejected public input boundaries.
    #[must_use]
    #[inline(always)]
    pub const fn presented_input_bytes(self) -> usize {
        self.presented_input_bytes
    }

    /// Returns the bytes the transaction actually inspected.
    ///
    /// # Returns
    ///
    /// Source bytes successfully admitted for inspection, even if later
    /// discarded.
    #[must_use]
    #[inline(always)]
    pub const fn inspected_input_bytes(self) -> usize {
        self.inspected_input_bytes
    }

    /// Returns the final escaped bytes retained by the transaction.
    ///
    /// # Returns
    ///
    /// Escaped bytes retained in the completed text or batch output.
    #[must_use]
    #[inline(always)]
    pub const fn output_bytes(self) -> usize {
        self.output_bytes
    }

    /// Returns the admitted domain or format nodes visited by the transaction.
    ///
    /// # Returns
    ///
    /// Structural nodes successfully admitted during traversal.
    #[must_use]
    #[inline(always)]
    pub const fn visited_nodes(self) -> usize {
        self.visited_nodes
    }

    /// Returns the admitted collection items visited by the transaction.
    ///
    /// # Returns
    ///
    /// Sequence and map entries successfully admitted during traversal.
    #[must_use]
    #[inline(always)]
    pub const fn visited_collection_items(self) -> usize {
        self.visited_collection_items
    }

    /// Returns the greatest active structural depth observed by the
    /// transaction.
    ///
    /// # Returns
    ///
    /// The greatest active structural depth, or zero when no node was admitted.
    #[must_use]
    #[inline(always)]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Returns omitted source bytes when the source length is known.
    ///
    /// # Returns
    ///
    /// `Some(bytes)` counts known omissions; `None` means at least one source
    /// had unknown total length, so the aggregate omission is unknown.
    #[must_use]
    #[inline(always)]
    pub const fn omitted_input_bytes(self) -> Option<usize> {
        self.omitted_input_bytes
    }

    /// Adds bytes written to the final output buffer.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Additional retained output bytes.
    ///
    /// # Returns
    ///
    /// A copy with output bytes added using saturating arithmetic.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn with_added_output_bytes(mut self, bytes: usize) -> Self {
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        self
    }

    /// Records input supplied to and, when admitted, inspected by an adapter.
    ///
    /// # Parameters
    ///
    /// - `presented`: Additional source bytes presented at the boundary.
    /// - `inspected`: Additional source bytes admitted for inspection.
    ///
    /// # Returns
    ///
    /// A copy with cumulative byte counts and known omissions updated;
    /// previously unknown omissions remain unknown.
    #[must_use]
    #[inline]
    pub(crate) const fn with_input(mut self, presented: usize, inspected: usize) -> Self {
        self.presented_input_bytes = self.presented_input_bytes.saturating_add(presented);
        self.inspected_input_bytes = self.inspected_input_bytes.saturating_add(inspected);
        self.omitted_input_bytes = match self.omitted_input_bytes {
            Some(omitted) => Some(omitted.saturating_add(presented.saturating_sub(inspected))),
            None => None,
        };
        self
    }

    /// Records input whose omitted-byte count is supplied by the source.
    ///
    /// # Parameters
    ///
    /// - `presented`: Additional source bytes presented at the boundary.
    /// - `inspected`: Additional source bytes admitted for inspection.
    /// - `omitted`: Some known omitted bytes, or None when the total source
    ///   length is unknown.
    ///
    /// # Returns
    ///
    /// A copy with cumulative input counts and source-reported omissions;
    /// any unknown omission makes the aggregate unknown.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline]
    pub(crate) const fn with_source_input(
        mut self,
        presented: usize,
        inspected: usize,
        omitted: Option<usize>,
    ) -> Self {
        self.presented_input_bytes = self.presented_input_bytes.saturating_add(presented);
        self.inspected_input_bytes = self.inspected_input_bytes.saturating_add(inspected);
        self.omitted_input_bytes = match (self.omitted_input_bytes, omitted) {
            (Some(previous), Some(current)) => Some(previous.saturating_add(current)),
            _ => None,
        };
        self
    }

    /// Records one admitted structural node.
    ///
    /// # Parameters
    ///
    /// - `depth`: Active structural depth of the newly admitted node.
    ///
    /// # Returns
    ///
    /// A copy counting one additional node and retaining the greatest depth.
    #[must_use]
    #[inline]
    pub(crate) const fn with_domain_node(mut self, depth: usize) -> Self {
        self.visited_nodes = self.visited_nodes.saturating_add(1);
        self.max_depth = if self.max_depth > depth { self.max_depth } else { depth };
        self
    }

    /// Records one admitted collection item.
    ///
    /// # Returns
    ///
    /// A copy counting one additional collection item using saturating
    /// arithmetic.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn with_collection_item(mut self) -> Self {
        self.visited_collection_items = self.visited_collection_items.saturating_add(1);
        self
    }
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! One unpublished publication buffer selected when a runtime is created.

use super::batch_output_buffer::BatchOutputBuffer;
use super::text_output_buffer::TextOutputBuffer;
use crate::RedactedText;
use crate::RedactionTextOutput;

/// Stores exactly one publication model for one runtime transaction.
pub(super) enum PublicationBuffer {
    /// Ordered text owned by a composer.
    Text(TextOutputBuffer),
    /// Independently resolvable items owned by a batch.
    Batch(BatchOutputBuffer),
    /// No publication storage for a non-rendering inspection.
    Inspection,
}

impl PublicationBuffer {
    /// Creates the composer publication model.
    pub(super) const fn text() -> Self {
        Self::Text(TextOutputBuffer::new())
    }

    /// Creates the batch publication model.
    pub(super) const fn batch() -> Self {
        Self::Batch(BatchOutputBuffer::new())
    }

    /// Creates the storage-free inspection publication model.
    pub(super) const fn inspection() -> Self {
        Self::Inspection
    }

    /// Reports whether this runtime publishes ordered text.
    pub(super) const fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Reports whether this runtime publishes independently resolvable items.
    pub(super) const fn is_batch(&self) -> bool {
        matches!(self, Self::Batch(_))
    }

    /// Reports whether this runtime performs non-rendering inspection.
    pub(super) const fn is_inspection(&self) -> bool {
        matches!(self, Self::Inspection)
    }

    /// Returns the text buffer selected for a composer runtime.
    pub(super) fn text_mut(&mut self) -> &mut TextOutputBuffer {
        match self {
            Self::Text(buffer) => buffer,
            Self::Batch(_) => panic!("a batch runtime cannot publish aggregate text"),
            Self::Inspection => panic!("an inspection runtime cannot publish aggregate text"),
        }
    }

    /// Returns the item buffer selected for a batch runtime.
    pub(super) fn batch_mut(&mut self) -> &mut BatchOutputBuffer {
        match self {
            Self::Text(_) => panic!("a text composer runtime cannot publish batch items"),
            Self::Batch(buffer) => buffer,
            Self::Inspection => panic!("an inspection runtime cannot publish batch items"),
        }
    }

    /// Publishes the text selected for a composer runtime.
    pub(super) fn into_text(self) -> RedactedText {
        match self {
            Self::Text(buffer) => buffer.publish(),
            Self::Batch(_) => panic!("a batch runtime cannot publish text"),
            Self::Inspection => panic!("an inspection runtime cannot publish text"),
        }
    }

    /// Publishes the items selected for a batch runtime.
    pub(super) fn into_batch(self) -> Vec<RedactionTextOutput> {
        match self {
            Self::Text(_) => panic!("a text composer runtime cannot publish batch items"),
            Self::Batch(buffer) => buffer.publish(),
            Self::Inspection => panic!("an inspection runtime cannot publish batch items"),
        }
    }

    /// Consumes and validates the storage-free inspection publication model.
    pub(super) fn finish_inspection(self) {
        match self {
            Self::Inspection => {}
            Self::Text(_) => panic!("a text composer runtime cannot finish inspection"),
            Self::Batch(_) => panic!("a batch runtime cannot finish inspection"),
        }
    }
}

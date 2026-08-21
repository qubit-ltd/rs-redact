// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
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

    /// Reports whether this runtime publishes ordered text.
    pub(super) const fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Returns the text buffer selected for a composer runtime.
    pub(super) fn text_mut(&mut self) -> &mut TextOutputBuffer {
        match self {
            Self::Text(buffer) => buffer,
            Self::Batch(_) => panic!("a batch runtime cannot publish aggregate text"),
        }
    }

    /// Returns the item buffer selected for a batch runtime.
    pub(super) fn batch_mut(&mut self) -> &mut BatchOutputBuffer {
        match self {
            Self::Text(_) => panic!("a text composer runtime cannot publish batch items"),
            Self::Batch(buffer) => buffer,
        }
    }

    /// Publishes the text selected for a composer runtime.
    pub(super) fn into_text(self) -> RedactedText {
        match self {
            Self::Text(buffer) => buffer.publish(),
            Self::Batch(_) => panic!("a batch runtime cannot publish text"),
        }
    }

    /// Publishes the items selected for a batch runtime.
    pub(super) fn into_batch(self) -> Vec<RedactionTextOutput> {
        match self {
            Self::Text(_) => panic!("a text composer runtime cannot publish batch items"),
            Self::Batch(buffer) => buffer.publish(),
        }
    }
}

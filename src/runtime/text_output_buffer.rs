// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished ordered text owned by the text-composition publication path.

use crate::RedactedText;

pub(super) struct TextOutputBuffer {
    storage: String,
}

impl TextOutputBuffer {
    #[must_use]
    pub(super) const fn new() -> Self {
        Self { storage: String::new() }
    }

    pub(super) fn push(&mut self, text: &str) {
        self.storage.push_str(text);
    }

    #[must_use]
    pub(super) fn publish(self) -> RedactedText {
        RedactedText::from_escaped(self.storage)
    }
}

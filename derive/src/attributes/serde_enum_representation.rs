// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Supported Serde enum representations.

/// Validated representation used by the redacted serialization backend.
#[must_use]
pub(crate) enum SerdeEnumRepresentation {
    /// Serde's default `{ "Variant": content }` representation.
    ExternallyTagged,
    /// A tag field merged into valid variant content.
    InternallyTagged {
        /// Serialized field carrying the variant name.
        tag: String,
    },
    /// Separate tag and content fields.
    AdjacentlyTagged {
        /// Serialized field carrying the variant name.
        tag: String,
        /// Serialized field carrying variant content.
        content: String,
    },
    /// Variant content without a tag.
    Untagged,
}

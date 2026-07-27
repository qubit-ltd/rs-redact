// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Trait-name suffixes used by generated capability assertions.

use crate::field_mode::FieldMode;

/// Supplies the trait-name suffixes used by generated helper identifiers.
pub(crate) trait ImmutableTraitName {
    /// Returns the required immutable capability name.
    ///
    /// # Returns
    ///
    /// The trait suffix used by immutable assertion helpers.
    fn immutable_trait_name(&self) -> &str;

    /// Returns the required destructive capability name.
    ///
    /// # Returns
    ///
    /// The trait suffix used by destructive assertion helpers.
    fn mutable_trait_name(&self) -> &str;

    /// Returns the required serialization capability name.
    ///
    /// # Returns
    ///
    /// The trait suffix used by serialization assertion helpers.
    fn serialization_trait_name(&self) -> &str;
}

impl ImmutableTraitName for FieldMode {
    /// Resolves the immutable capability represented by this field mode.
    ///
    /// # Returns
    ///
    /// The immutable trait suffix used in generated diagnostics.
    #[inline(always)]
    fn immutable_trait_name(&self) -> &str {
        match self {
            Self::Level(_) => "RedactValue",
            Self::Nested => "Redact",
            Self::Map => "RedactMapValue",
            Self::Plain | Self::Skip => "Unused",
        }
    }

    /// Resolves the destructive capability represented by this field mode.
    ///
    /// # Returns
    ///
    /// The destructive trait suffix used in generated diagnostics.
    #[inline(always)]
    fn mutable_trait_name(&self) -> &str {
        match self {
            Self::Level(_) => "RedactValueMut",
            Self::Nested => "RedactMut",
            Self::Map => "RedactMapValueMut",
            Self::Plain | Self::Skip => "Unused",
        }
    }

    /// Resolves the serialization capability represented by this field mode.
    ///
    /// # Returns
    ///
    /// The serialization trait suffix used in generated diagnostics.
    #[inline(always)]
    fn serialization_trait_name(&self) -> &str {
        match self {
            Self::Nested => "RedactSerialize",
            Self::Map => "RedactMapSerialize",
            Self::Plain | Self::Level(_) | Self::Skip => "Unused",
        }
    }
}

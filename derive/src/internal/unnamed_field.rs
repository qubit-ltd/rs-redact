// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed state for one unnamed derive field.

use syn::{
    Field,
    Index,
};

use crate::{
    field_attributes::FieldAttributes,
    serde_attributes::SerdeAttributes,
};

/// One positional field with validated redaction and serde attributes.
#[must_use]
pub(crate) struct UnnamedField<'a> {
    /// Original syntax node used to retain diagnostic spans.
    field: &'a Field,
    /// Stable zero-based field index.
    index: Index,
    /// Validated redaction controls.
    attributes: FieldAttributes,
    /// Validated or disabled serde controls.
    serde_attributes: SerdeAttributes,
}

impl<'a> UnnamedField<'a> {
    /// Creates parsed state for one positional field.
    ///
    /// # Parameters
    ///
    /// * `field` - Original field syntax node.
    /// * `index` - Stable zero-based field index.
    /// * `attributes` - Validated redaction controls.
    /// * `serde_attributes` - Validated or disabled serde controls.
    ///
    /// # Returns
    ///
    /// Parsed positional field state retaining source spans and controls.
    #[inline(always)]
    pub(crate) const fn new(
        field: &'a Field,
        index: Index,
        attributes: FieldAttributes,
        serde_attributes: SerdeAttributes,
    ) -> Self {
        Self {
            field,
            index,
            attributes,
            serde_attributes,
        }
    }

    /// Returns the original field syntax node.
    ///
    /// # Returns
    ///
    /// The field used for span-aware generated tokens.
    #[inline(always)]
    pub(crate) const fn field(&self) -> &'a Field {
        self.field
    }

    /// Returns the stable positional index.
    ///
    /// # Returns
    ///
    /// The index used in generated member access and diagnostics.
    #[inline(always)]
    pub(crate) const fn index(&self) -> &Index {
        &self.index
    }

    /// Returns the validated redaction controls.
    ///
    /// # Returns
    ///
    /// The field's unique redaction mode.
    #[inline(always)]
    pub(crate) const fn attributes(&self) -> &FieldAttributes {
        &self.attributes
    }

    /// Returns the parsed serde controls.
    ///
    /// # Returns
    ///
    /// Enabled controls or an empty disabled state.
    #[inline(always)]
    pub(crate) const fn serde_attributes(&self) -> &SerdeAttributes {
        &self.serde_attributes
    }
}

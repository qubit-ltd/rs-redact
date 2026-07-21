// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed state for one named derive field.

use syn::{
    Field,
    Ident,
};

use crate::{
    field_attributes::FieldAttributes,
    serde_attributes::SerdeAttributes,
};

/// One named field with validated redaction and serde attributes.
#[must_use]
pub(crate) struct NamedField<'a> {
    /// Original syntax node used to retain diagnostic spans.
    field: &'a Field,
    /// Field identifier.
    identifier: &'a Ident,
    /// Validated redaction controls.
    attributes: FieldAttributes,
    /// Validated or disabled serde controls.
    serde_attributes: SerdeAttributes,
}

impl<'a> NamedField<'a> {
    /// Creates parsed state for one named field.
    ///
    /// # Parameters
    ///
    /// * `field` - Original field syntax node.
    /// * `identifier` - Field identifier.
    /// * `attributes` - Validated redaction controls.
    /// * `serde_attributes` - Validated or disabled serde controls.
    ///
    /// # Returns
    ///
    /// Parsed field state retaining source spans and controls.
    #[inline(always)]
    pub(crate) const fn new(
        field: &'a Field,
        identifier: &'a Ident,
        attributes: FieldAttributes,
        serde_attributes: SerdeAttributes,
    ) -> Self {
        Self {
            field,
            identifier,
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

    /// Returns the field identifier.
    ///
    /// # Returns
    ///
    /// The identifier used in generated member access.
    #[inline(always)]
    pub(crate) const fn identifier(&self) -> &'a Ident {
        self.identifier
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

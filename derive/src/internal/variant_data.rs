// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed state for one enum variant.

use syn::Variant;

use crate::{
    internal::FieldsData,
    serde_variant_attributes::SerdeVariantAttributes,
};

/// One enum variant with its declaration index and validated fields.
#[must_use]
pub(crate) struct VariantData<'a> {
    /// Original variant syntax node used for names and spans.
    variant: &'a Variant,
    /// Stable zero-based declaration index used by serialization.
    index: u32,
    /// Validated variant field shape.
    fields: FieldsData<'a>,
    /// Validated serialization-only variant controls.
    serde_attributes: SerdeVariantAttributes,
}

impl<'a> VariantData<'a> {
    /// Creates parsed state for one enum variant.
    ///
    /// # Parameters
    ///
    /// * `variant` - Original variant syntax node.
    /// * `index` - Stable zero-based declaration index.
    /// * `fields` - Validated variant field shape.
    /// * `serde_attributes` - Validated serialization-only variant controls.
    ///
    /// # Returns
    ///
    /// Parsed variant data retaining source order and spans.
    #[inline(always)]
    pub(crate) const fn new(
        variant: &'a Variant,
        index: u32,
        fields: FieldsData<'a>,
        serde_attributes: SerdeVariantAttributes,
    ) -> Self {
        Self {
            variant,
            index,
            fields,
            serde_attributes,
        }
    }

    /// Returns the original variant syntax node.
    ///
    /// # Returns
    ///
    /// The variant carrying its identifier and source span.
    #[inline(always)]
    pub(crate) const fn variant(&self) -> &'a Variant {
        self.variant
    }

    /// Returns the stable declaration index.
    ///
    /// # Returns
    ///
    /// The zero-based index used by serializer variant APIs.
    #[inline(always)]
    pub(crate) const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the validated variant fields.
    ///
    /// # Returns
    ///
    /// Named, unnamed, or unit fields in source order.
    #[inline(always)]
    pub(crate) const fn fields(&self) -> &FieldsData<'a> {
        &self.fields
    }

    /// Returns the validated serialization-only variant controls.
    ///
    /// # Returns
    ///
    /// Variant naming, field renaming, and skip state.
    #[inline(always)]
    pub(crate) const fn serde_attributes(&self) -> &SerdeVariantAttributes {
        &self.serde_attributes
    }
}

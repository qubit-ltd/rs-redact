// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Whitelisted Serde container attributes for redacted serialization.

use syn::{DeriveInput, LitStr, spanned::Spanned};

use crate::{
    internal::SerdeContainerAttributeParser, serde_enum_representation::SerdeEnumRepresentation,
    serde_rename_rule::SerdeRenameRule,
};

/// Validated names, rename rules, and enum representation.
#[must_use]
pub(crate) struct SerdeContainerAttributes {
    /// Serialized container name.
    name: String,
    /// Struct-field or enum-variant rename rule.
    rename_all: Option<SerdeRenameRule>,
    /// Enum variant-field rename rule.
    rename_all_fields: Option<SerdeRenameRule>,
    /// Validated enum representation.
    representation: SerdeEnumRepresentation,
}

impl SerdeContainerAttributes {
    /// Parses the safe serialization-only Serde container allowlist.
    ///
    /// # Parameters
    ///
    /// * `input` - Complete derive input carrying container attributes.
    /// * `enabled` - Whether `#[redact(serde)]` requested parsing.
    ///
    /// # Returns
    ///
    /// Validated names, rename rules, and representation.
    ///
    /// # Errors
    ///
    /// Returns a targeted error for unsupported attributes, duplicates,
    /// invalid representation combinations, or enum-only controls on structs.
    #[inline(always)]
    pub(crate) fn parse(input: &DeriveInput, enabled: bool) -> syn::Result<Self> {
        SerdeContainerAttributeParser::parse(input, enabled)
    }

    /// Builds validated attributes from parser-owned container controls.
    ///
    /// # Parameters
    ///
    /// * `input` - Complete derive input carrying the container identity.
    /// * `name` - Optional explicit serialized container name.
    /// * `rename_all` - Optional struct-field or enum-variant rename rule.
    /// * `rename_all_fields` - Optional enum variant-field rename rule.
    /// * `tag` - Optional internal or adjacent enum tag.
    /// * `content` - Optional adjacent enum content key.
    /// * `untagged` - Optional bare untagged attribute path.
    ///
    /// # Returns
    ///
    /// Attributes with a validated enum representation.
    ///
    /// # Errors
    ///
    /// Returns the targeted representation validation error for incompatible
    /// tag, content, or untagged controls.
    pub(super) fn from_parts(
        input: &DeriveInput,
        name: Option<String>,
        rename_all: Option<SerdeRenameRule>,
        rename_all_fields: Option<SerdeRenameRule>,
        tag: Option<LitStr>,
        content: Option<LitStr>,
        untagged: Option<syn::Path>,
    ) -> syn::Result<Self> {
        let representation = representation(input, tag, content, untagged)?;
        Ok(Self {
            name: name.unwrap_or_else(|| input.ident.to_string()),
            rename_all,
            rename_all_fields,
            representation,
        })
    }

    /// Returns the serialized container name.
    ///
    /// # Returns
    ///
    /// An explicit `rename` or the Rust type identifier.
    #[inline(always)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Applies the struct field rename rule.
    ///
    /// # Parameters
    ///
    /// * `field_name` - Rust field identifier without a raw prefix.
    ///
    /// # Returns
    ///
    /// The serialized struct field name.
    pub(crate) fn rename_struct_field(&self, field_name: &str) -> String {
        self.rename_all.as_ref().map_or_else(
            || field_name.to_owned(),
            |rule| rule.apply_to_field(field_name),
        )
    }

    /// Applies the enum variant rename rule.
    ///
    /// # Parameters
    ///
    /// * `variant_name` - Rust variant identifier.
    ///
    /// # Returns
    ///
    /// The serialized variant name.
    pub(crate) fn rename_variant(&self, variant_name: &str) -> String {
        self.rename_all.as_ref().map_or_else(
            || variant_name.to_owned(),
            |rule| rule.apply_to_variant(variant_name),
        )
    }

    /// Applies the container-wide enum field rename rule.
    ///
    /// # Parameters
    ///
    /// * `field_name` - Rust field identifier without a raw prefix.
    ///
    /// # Returns
    ///
    /// The serialized variant field name.
    pub(crate) fn rename_variant_field(&self, field_name: &str) -> String {
        self.rename_all_fields.as_ref().map_or_else(
            || field_name.to_owned(),
            |rule| rule.apply_to_field(field_name),
        )
    }

    /// Returns the validated enum representation.
    ///
    /// # Returns
    ///
    /// Externally tagged, internally tagged, adjacently tagged, or untagged.
    #[inline(always)]
    pub(crate) const fn representation(&self) -> &SerdeEnumRepresentation {
        &self.representation
    }
}

/// Validates and selects one enum representation.
fn representation(
    input: &DeriveInput,
    tag: Option<LitStr>,
    content: Option<LitStr>,
    untagged: Option<syn::Path>,
) -> syn::Result<SerdeEnumRepresentation> {
    if let Some(path) = untagged {
        if tag.is_some() || content.is_some() {
            return Err(syn::Error::new(
                path.span(),
                format!(
                    "Redact serde for `{}` cannot combine `untagged` with `tag` or `content`",
                    input.ident,
                ),
            ));
        }
        return Ok(SerdeEnumRepresentation::Untagged);
    }
    match (tag, content) {
        (None, None) => Ok(SerdeEnumRepresentation::ExternallyTagged),
        (None, Some(content)) => Err(syn::Error::new_spanned(
            content,
            format!(
                "Redact serde for `{}` requires `tag` when `content` is present",
                input.ident,
            ),
        )),
        (Some(tag), None) => Ok(SerdeEnumRepresentation::InternallyTagged { tag: tag.value() }),
        (Some(tag), Some(content)) => {
            if tag.value() == content.value() {
                return Err(syn::Error::new_spanned(
                    content,
                    format!(
                        "Redact serde for `{}` requires distinct `tag` and `content` names",
                        input.ident,
                    ),
                ));
            }
            Ok(SerdeEnumRepresentation::AdjacentlyTagged {
                tag: tag.value(),
                content: content.value(),
            })
        }
    }
}

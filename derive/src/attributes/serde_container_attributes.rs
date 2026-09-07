// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Whitelisted Serde container attributes for redacted serialization.

use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Fields;
use syn::LitStr;
use syn::Path;
use syn::Result;
use syn::spanned::Spanned;

use super::SerdeContainerAttributeParser;
use super::SerdeEnumRepresentation;
use super::SerdeRenameRule;
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
    /// Whether a single-field struct serializes as its field.
    transparent: bool,
}

impl SerdeContainerAttributes {
    /// Parses the safe serialization-only Serde container allowlist.
    ///
    /// # Parameters
    ///
    /// * `input` - Complete derive input carrying container attributes.
    /// * `enabled` - Whether Serde projection generation requires parsing.
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
    pub(crate) fn parse(input: &DeriveInput, enabled: bool) -> Result<Self> {
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
    /// * `transparent` - Whether a single-field struct uses its field
    ///   representation.
    ///
    /// # Returns
    ///
    /// Attributes with a validated enum representation.
    ///
    /// # Errors
    ///
    /// Returns the targeted representation validation error for incompatible
    /// tag, content, or untagged controls, or for `transparent` on anything
    /// other than a single-field struct.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_parts(
        input: &DeriveInput,
        name: Option<String>,
        rename_all: Option<SerdeRenameRule>,
        rename_all_fields: Option<SerdeRenameRule>,
        tag: Option<LitStr>,
        content: Option<LitStr>,
        untagged: Option<Path>,
        transparent: bool,
    ) -> Result<Self> {
        if transparent {
            let valid = matches!(&input.data, Data::Struct(data) if match &data.fields {
                Fields::Named(fields) => fields.named.len() == 1,
                Fields::Unnamed(fields) => fields.unnamed.len() == 1,
                Fields::Unit => false,
            });
            if !valid {
                return Err(Error::new_spanned(
                    input,
                    format!(
                        "Redact serde for `{}` requires `transparent` on a single-field struct",
                        input.ident
                    ),
                ));
            }
        }
        let representation = representation(input, tag, content, untagged)?;
        Ok(Self {
            name: name.unwrap_or_else(|| input.ident.to_string()),
            rename_all,
            rename_all_fields,
            representation,
            transparent,
        })
    }

    /// Returns the serialized container name.
    ///
    /// # Returns
    ///
    /// An explicit `rename` or the Rust type identifier.
    #[must_use]
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
    #[must_use]
    #[inline]
    pub(crate) fn rename_struct_field(&self, field_name: &str) -> String {
        self.rename_all
            .as_ref()
            .map_or_else(|| field_name.to_owned(), |rule| rule.apply_to_field(field_name))
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
    #[must_use]
    #[inline]
    pub(crate) fn rename_variant(&self, variant_name: &str) -> String {
        self.rename_all
            .as_ref()
            .map_or_else(|| variant_name.to_owned(), |rule| rule.apply_to_variant(variant_name))
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
    #[must_use]
    #[inline]
    pub(crate) fn rename_variant_field(&self, field_name: &str) -> String {
        self.rename_all_fields
            .as_ref()
            .map_or_else(|| field_name.to_owned(), |rule| rule.apply_to_field(field_name))
    }

    /// Returns the validated enum representation.
    ///
    /// # Returns
    ///
    /// Externally tagged, internally tagged, adjacently tagged, or untagged.
    #[must_use = "the selected representation determines generated serialization"]
    #[inline(always)]
    pub(crate) const fn representation(&self) -> &SerdeEnumRepresentation {
        &self.representation
    }

    /// Returns whether a single-field struct uses the field representation.
    ///
    /// # Returns
    ///
    /// `true` when the validated container declares `serde(transparent)`.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn transparent(&self) -> bool {
        self.transparent
    }
}

/// Validates and selects one enum representation.
///
/// # Parameters
///
/// * `input` - Owning derive input used in diagnostics.
/// * `tag` - Optional serialized variant tag key.
/// * `content` - Optional separately serialized variant content key.
/// * `untagged` - Optional untagged control used as the diagnostic span.
///
/// # Returns
///
/// The selected external, internal, adjacent, or untagged representation.
///
/// # Errors
///
/// Rejects `untagged` combined with a tag or content key, content without a
/// tag, and identical adjacent tag and content keys.
fn representation(
    input: &DeriveInput,
    tag: Option<LitStr>,
    content: Option<LitStr>,
    untagged: Option<Path>,
) -> Result<SerdeEnumRepresentation> {
    if let Some(path) = untagged {
        if tag.is_some() || content.is_some() {
            return Err(Error::new(
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
        (None, Some(content)) => Err(Error::new_spanned(
            content,
            format!(
                "Redact serde for `{}` requires `tag` when `content` is present",
                input.ident,
            ),
        )),
        (Some(tag), None) => Ok(SerdeEnumRepresentation::InternallyTagged { tag: tag.value() }),
        (Some(tag), Some(content)) => {
            if tag.value() == content.value() {
                return Err(Error::new_spanned(
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

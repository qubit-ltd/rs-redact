// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Whitelisted Serde container attributes for redacted serialization.

use syn::{
    Data,
    DeriveInput,
    LitStr,
    Meta,
    Token,
    spanned::Spanned,
};

use crate::{
    serde_enum_representation::SerdeEnumRepresentation,
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
    pub(crate) fn parse(
        input: &DeriveInput,
        enabled: bool,
    ) -> syn::Result<Self> {
        let mut name = None;
        let mut rename_all = None;
        let mut rename_all_fields = None;
        let mut tag = None;
        let mut content = None;
        let mut untagged = None;

        if enabled {
            for attribute in &input.attrs {
                if !attribute.path().is_ident("serde") {
                    continue;
                }
                let Meta::List(_) = &attribute.meta else {
                    return Err(syn::Error::new_spanned(
                        attribute,
                        format!(
                            "Redact serde for `{}` expects `#[serde(...)]`",
                            input.ident,
                        ),
                    ));
                };
                attribute.parse_nested_meta(|meta| {
                    if meta.path.is_ident("rename") {
                        parse_name(&meta, &input.ident, "rename", &mut name)
                    } else if meta.path.is_ident("rename_all") {
                        parse_rule(
                            &meta,
                            &input.ident,
                            "rename_all",
                            &mut rename_all,
                        )
                    } else if meta.path.is_ident("rename_all_fields") {
                        if !matches!(input.data, Data::Enum(_)) {
                            return Err(meta.error(format!(
                                "Redact serde for `{}` allows `rename_all_fields` only on enums",
                                input.ident,
                            )));
                        }
                        parse_rule(
                            &meta,
                            &input.ident,
                            "rename_all_fields",
                            &mut rename_all_fields,
                        )
                    } else if meta.path.is_ident("tag") {
                        require_enum(&meta, input, "tag")?;
                        parse_literal(&meta, &input.ident, "tag", &mut tag)
                    } else if meta.path.is_ident("content") {
                        require_enum(&meta, input, "content")?;
                        parse_literal(&meta, &input.ident, "content", &mut content)
                    } else if meta.path.is_ident("untagged") {
                        require_enum(&meta, input, "untagged")?;
                        if meta.input.peek(Token![=])
                            || meta.input.peek(syn::token::Paren)
                        {
                            return Err(meta.error(format!(
                                "Redact serde for `{}` requires bare `untagged`",
                                input.ident,
                            )));
                        }
                        if untagged.is_some() {
                            return Err(meta.error(format!(
                                "Redact serde for `{}` repeats `untagged`",
                                input.ident,
                            )));
                        }
                        untagged = Some(meta.path.clone());
                        Ok(())
                    } else {
                        let key = meta
                            .path
                            .segments
                            .last()
                            .map(|segment| segment.ident.to_string())
                            .unwrap_or_else(|| "unknown".to_owned());
                        Err(meta.error(format!(
                            "Redact serde for `{}` does not support container `{key}` because it can change value paths or bypass redaction; use only `rename`, `rename_all`, `rename_all_fields`, `tag`, `content`, or `untagged`",
                            input.ident,
                        )))
                    }
                })?;
            }
        }

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

/// Requires one Serde control to appear on an enum.
///
/// # Parameters
///
/// * `meta` - Nested attribute item used as the error span.
/// * `input` - Complete derive input.
/// * `name` - Enum-only control name.
///
/// # Errors
///
/// Returns a targeted error when the derive input is not an enum.
fn require_enum(
    meta: &syn::meta::ParseNestedMeta<'_>,
    input: &DeriveInput,
    name: &str,
) -> syn::Result<()> {
    if matches!(input.data, Data::Enum(_)) {
        Ok(())
    } else {
        Err(meta.error(format!(
            "Redact serde for `{}` allows `{name}` only on enums",
            input.ident,
        )))
    }
}

/// Parses one unique string name.
fn parse_name(
    meta: &syn::meta::ParseNestedMeta<'_>,
    type_name: &syn::Ident,
    name: &str,
    output: &mut Option<String>,
) -> syn::Result<()> {
    if output.is_some() {
        return Err(meta.error(format!(
            "Redact serde for `{type_name}` repeats `{name}`",
        )));
    }
    let mut literal = None;
    parse_literal(meta, type_name, name, &mut literal)?;
    *output = literal.map(|literal| literal.value());
    Ok(())
}

/// Parses one unique rename rule.
fn parse_rule(
    meta: &syn::meta::ParseNestedMeta<'_>,
    type_name: &syn::Ident,
    name: &str,
    output: &mut Option<SerdeRenameRule>,
) -> syn::Result<()> {
    if output.is_some() {
        return Err(meta.error(format!(
            "Redact serde for `{type_name}` repeats `{name}`",
        )));
    }
    let literal: LitStr = meta.value()?.parse()?;
    *output = Some(SerdeRenameRule::parse(&literal)?);
    Ok(())
}

/// Parses one unique string literal while retaining its diagnostic span.
fn parse_literal(
    meta: &syn::meta::ParseNestedMeta<'_>,
    type_name: &syn::Ident,
    name: &str,
    output: &mut Option<LitStr>,
) -> syn::Result<()> {
    if output.is_some() {
        return Err(meta.error(format!(
            "Redact serde for `{type_name}` repeats `{name}`",
        )));
    }
    *output = Some(meta.value()?.parse()?);
    Ok(())
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
        (Some(tag), None) => {
            Ok(SerdeEnumRepresentation::InternallyTagged { tag: tag.value() })
        }
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

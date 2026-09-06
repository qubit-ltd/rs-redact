// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parser for the supported Serde container attribute allowlist.
// qubit-style: allow type-file-name

use syn::Attribute;
use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Ident;
use syn::LitStr;
use syn::Meta;
use syn::Path;
use syn::Result;
use syn::Token;
use syn::meta::ParseNestedMeta;
use syn::token::Paren;

use super::parse_serialize_name;
use crate::attributes::SerdeContainerAttributes;
use crate::attributes::SerdeRenameRule;
/// Incremental state for Serde container attribute parsing.
///
/// # Type Parameters
///
/// * `'input` - Lifetime of the borrowed derive input being parsed.
pub(crate) struct SerdeContainerAttributeParser<'input> {
    /// Complete derive input that owns the parsed attributes.
    input: &'input DeriveInput,
    /// Optional explicit serialized container name.
    name: Option<String>,
    /// Whether direct or directional container rename occurred.
    name_seen: bool,
    /// Optional struct-field or enum-variant rename rule.
    rename_all: Option<SerdeRenameRule>,
    /// Whether direct or directional `rename_all` occurred.
    rename_all_seen: bool,
    /// Optional enum variant-field rename rule.
    rename_all_fields: Option<SerdeRenameRule>,
    /// Whether direct or directional `rename_all_fields` occurred.
    rename_all_fields_seen: bool,
    /// Optional internal or adjacent enum tag.
    tag: Option<LitStr>,
    /// Optional adjacent enum content key.
    content: Option<LitStr>,
    /// Optional bare untagged attribute path.
    untagged: Option<Path>,
    /// Whether a single-field struct uses its field representation directly.
    transparent: bool,
}

impl<'input> SerdeContainerAttributeParser<'input> {
    /// Parses supported Serde container controls into validated attributes.
    ///
    /// # Parameters
    ///
    /// * `input` - Complete derive input carrying container attributes.
    /// * `enabled` - Whether `#[redact(serde)]` requested parsing.
    ///
    /// # Returns
    ///
    /// Validated serialization attributes, or default attributes when parsing
    /// is disabled.
    ///
    /// # Errors
    ///
    /// Returns targeted errors for malformed, duplicate, enum-only, or
    /// unsupported controls and incompatible enum representations.
    ///
    /// # Panics
    ///
    /// Panics only if `syn` supplies a nested metadata path without any
    /// segments, which violates the `ParseNestedMeta` path invariant.
    pub(crate) fn parse(input: &'input DeriveInput, enabled: bool) -> Result<SerdeContainerAttributes> {
        let mut parser = Self::new(input);
        parser.parse_attributes(enabled)?;
        parser.finish()
    }

    /// Creates an empty parser for one derive input.
    ///
    /// # Parameters
    ///
    /// * `input` - Complete derive input carrying container attributes.
    ///
    /// # Returns
    ///
    /// Parser state with no controls collected.
    #[must_use]
    #[inline(always)]
    fn new(input: &'input DeriveInput) -> Self {
        Self {
            input,
            name: None,
            name_seen: false,
            rename_all: None,
            rename_all_seen: false,
            rename_all_fields: None,
            rename_all_fields_seen: false,
            tag: None,
            content: None,
            untagged: None,
            transparent: false,
        }
    }

    /// Parses every supported Serde container attribute when enabled.
    ///
    /// # Parameters
    ///
    /// * `enabled` - Whether `#[redact(serde)]` requested parsing.
    ///
    /// # Errors
    ///
    /// Returns the first malformed or unsupported Serde attribute error.
    fn parse_attributes(&mut self, enabled: bool) -> Result<()> {
        if !enabled {
            return Ok(());
        }
        for attribute in &self.input.attrs {
            if attribute.path().is_ident("serde") {
                self.parse_attribute(attribute)?;
            }
        }
        Ok(())
    }

    /// Parses one `#[serde(...)]` container attribute.
    ///
    /// # Parameters
    ///
    /// * `attribute` - Serde attribute selected from the derive input.
    ///
    /// # Errors
    ///
    /// Returns an error when the attribute is not list-shaped or contains an
    /// unsupported nested control.
    fn parse_attribute(&mut self, attribute: &Attribute) -> Result<()> {
        let Meta::List(_) = &attribute.meta else {
            return Err(Error::new_spanned(
                attribute,
                format!("Redact serde for `{}` expects `#[serde(...)]`", self.input.ident,),
            ));
        };
        attribute.parse_nested_meta(|meta| self.parse_nested_attribute(meta))
    }

    /// Parses one nested Serde container control.
    ///
    /// # Parameters
    ///
    /// * `meta` - Nested Serde metadata item.
    ///
    /// # Errors
    ///
    /// Returns a targeted error for duplicate, malformed, or unsupported
    /// controls.
    fn parse_nested_attribute(&mut self, meta: ParseNestedMeta<'_>) -> Result<()> {
        if meta.path.is_ident("rename") {
            parse_name(&meta, &self.input.ident, "rename", &mut self.name_seen, &mut self.name)
        } else if meta.path.is_ident("rename_all") {
            parse_rule(
                &meta,
                &self.input.ident,
                "rename_all",
                &mut self.rename_all_seen,
                &mut self.rename_all,
            )
        } else if meta.path.is_ident("rename_all_fields") {
            self.parse_rename_all_fields(meta)
        } else if meta.path.is_ident("tag") {
            self.parse_tag(meta)
        } else if meta.path.is_ident("content") {
            self.parse_content(meta)
        } else if meta.path.is_ident("untagged") {
            self.parse_untagged(meta)
        } else if meta.path.is_ident("crate") {
            let _: LitStr = meta.value()?.parse()?;
            Ok(())
        } else if meta.path.is_ident("transparent") {
            if meta.input.peek(Token![=]) || meta.input.peek(Paren) {
                return Err(meta.error(format!(
                    "Redact serde for `{}` requires bare `transparent`",
                    self.input.ident,
                )));
            }
            if self.transparent {
                return Err(meta.error(format!("Redact serde for `{}` repeats `transparent`", self.input.ident,)));
            }
            self.transparent = true;
            Ok(())
        } else if meta.path.is_ident("default") {
            parse_deserialize_only_default(&meta, &self.input.ident)
        } else if meta.path.is_ident("deny_unknown_fields") {
            require_bare_deserialize_only(&meta, &self.input.ident, "deny_unknown_fields")
        } else {
            Err(self.unsupported_control_error(meta))
        }
    }

    /// Parses the enum-only `rename_all_fields` control.
    ///
    /// # Parameters
    ///
    /// * `meta` - Nested `rename_all_fields` metadata item.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not an enum or the rule is invalid
    /// or repeated.
    fn parse_rename_all_fields(&mut self, meta: ParseNestedMeta<'_>) -> Result<()> {
        require_enum(&meta, self.input, "rename_all_fields")?;
        parse_rule(
            &meta,
            &self.input.ident,
            "rename_all_fields",
            &mut self.rename_all_fields_seen,
            &mut self.rename_all_fields,
        )
    }

    /// Parses the enum-only `tag` control.
    ///
    /// # Parameters
    ///
    /// * `meta` - Nested `tag` metadata item.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not an enum or the tag is invalid or
    /// repeated.
    fn parse_tag(&mut self, meta: ParseNestedMeta<'_>) -> Result<()> {
        require_enum(&meta, self.input, "tag")?;
        parse_literal(&meta, &self.input.ident, "tag", &mut self.tag)
    }

    /// Parses the enum-only `content` control.
    ///
    /// # Parameters
    ///
    /// * `meta` - Nested `content` metadata item.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not an enum or the content key is
    /// invalid or repeated.
    fn parse_content(&mut self, meta: ParseNestedMeta<'_>) -> Result<()> {
        require_enum(&meta, self.input, "content")?;
        parse_literal(&meta, &self.input.ident, "content", &mut self.content)
    }

    /// Parses one bare enum-only `untagged` control.
    ///
    /// # Parameters
    ///
    /// * `meta` - Nested `untagged` metadata item.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not an enum, the control has a value,
    /// or the control is repeated.
    fn parse_untagged(&mut self, meta: ParseNestedMeta<'_>) -> Result<()> {
        require_enum(&meta, self.input, "untagged")?;
        if meta.input.peek(Token![=]) || meta.input.peek(Paren) {
            return Err(meta.error(format!(
                "Redact serde for `{}` requires bare `untagged`",
                self.input.ident,
            )));
        }
        if self.untagged.is_some() {
            return Err(meta.error(format!("Redact serde for `{}` repeats `untagged`", self.input.ident,)));
        }
        self.untagged = Some(meta.path);
        Ok(())
    }

    /// Builds the existing attribute value from collected parser state.
    ///
    /// # Returns
    ///
    /// Validated attributes ready for macro expansion.
    ///
    /// # Errors
    ///
    /// Returns the targeted error for an invalid enum representation.
    fn finish(self) -> Result<SerdeContainerAttributes> {
        SerdeContainerAttributes::from_parts(
            self.input,
            self.name,
            self.rename_all,
            self.rename_all_fields,
            self.tag,
            self.content,
            self.untagged,
            self.transparent,
        )
    }

    /// Builds the unsupported-control diagnostic for one metadata item.
    ///
    /// # Parameters
    ///
    /// * `meta` - Unsupported nested Serde metadata item.
    ///
    /// # Returns
    ///
    /// The targeted diagnostic explaining the supported allowlist.
    ///
    /// # Panics
    ///
    /// Panics only if `syn` supplies a nested metadata path without any
    /// segments, which violates the `ParseNestedMeta` path invariant.
    fn unsupported_control_error(&self, meta: ParseNestedMeta<'_>) -> Error {
        let key = meta
            .path
            .segments
            .last()
            .expect("syn nested meta paths always contain a segment")
            .ident
            .to_string();
        meta.error(format!(
            "Redact serde for `{}` does not support container `{key}` because it can change value paths or bypass redaction; use only `rename`, `rename_all`, `rename_all_fields`, `tag`, `content`, `untagged`, or deserialization-only controls such as `default` and `deny_unknown_fields`",
            self.input.ident,
        ))
    }
}

/// Parses a container `default` control that affects only deserialization.
///
/// # Parameters
///
/// * `meta` - Nested `default` metadata item.
/// * `type_name` - Derived type used in targeted diagnostics.
///
/// # Errors
///
/// Returns an error when a valued default is not a string or a parenthesized
/// default is supplied.
fn parse_deserialize_only_default(meta: &ParseNestedMeta<'_>, type_name: &Ident) -> Result<()> {
    if meta.input.peek(Token![=]) {
        let _: LitStr = meta.value()?.parse()?;
        return Ok(());
    }
    if meta.input.peek(Paren) {
        return Err(meta.error(format!(
            "Redact serde for `{type_name}` requires bare `default` or `default = \"...\"`"
        )));
    }
    Ok(())
}

/// Parses one bare container control that affects only deserialization.
///
/// # Parameters
///
/// * `meta` - Nested deserialization-only metadata item.
/// * `type_name` - Derived type used in targeted diagnostics.
/// * `name` - Control name required to be bare.
///
/// # Errors
///
/// Returns an error when the control has a value or parenthesized arguments.
fn require_bare_deserialize_only(meta: &ParseNestedMeta<'_>, type_name: &Ident, name: &str) -> Result<()> {
    if meta.input.peek(Token![=]) || meta.input.peek(Paren) {
        return Err(meta.error(format!("Redact serde for `{type_name}` requires bare `{name}`")));
    }
    Ok(())
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
fn require_enum(meta: &ParseNestedMeta<'_>, input: &DeriveInput, name: &str) -> Result<()> {
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
///
/// # Parameters
///
/// * `meta` - Nested attribute item carrying the string literal.
/// * `type_name` - Derived type used in diagnostics.
/// * `name` - Supported control name.
/// * `output` - Destination for the parsed name.
///
/// # Errors
///
/// Returns an error when the control is repeated or its value is not a string.
fn parse_name(
    meta: &ParseNestedMeta<'_>,
    type_name: &Ident,
    name: &str,
    seen: &mut bool,
    output: &mut Option<String>,
) -> Result<()> {
    if *seen {
        return Err(meta.error(format!("Redact serde for `{type_name}` repeats `{name}`",)));
    }
    *output = parse_serialize_name(meta, name)?.map(|literal| literal.value());
    *seen = true;
    Ok(())
}

/// Parses one unique rename rule.
///
/// # Parameters
///
/// * `meta` - Nested attribute item carrying the rule literal.
/// * `type_name` - Derived type used in diagnostics.
/// * `name` - Supported control name.
/// * `output` - Destination for the parsed rename rule.
///
/// # Errors
///
/// Returns an error when the control is repeated or the rule is unsupported.
fn parse_rule(
    meta: &ParseNestedMeta<'_>,
    type_name: &Ident,
    name: &str,
    seen: &mut bool,
    output: &mut Option<SerdeRenameRule>,
) -> Result<()> {
    if *seen {
        return Err(meta.error(format!("Redact serde for `{type_name}` repeats `{name}`",)));
    }
    *output = parse_serialize_name(meta, name)?
        .map(|literal| SerdeRenameRule::parse(&literal))
        .transpose()?;
    *seen = true;
    Ok(())
}

/// Parses one unique string literal while retaining its diagnostic span.
///
/// # Parameters
///
/// * `meta` - Nested attribute item carrying the literal.
/// * `type_name` - Derived type used in diagnostics.
/// * `name` - Supported control name.
/// * `output` - Destination for the parsed literal.
///
/// # Errors
///
/// Returns an error when the control is repeated or its value is not a string.
fn parse_literal(meta: &ParseNestedMeta<'_>, type_name: &Ident, name: &str, output: &mut Option<LitStr>) -> Result<()> {
    if output.is_some() {
        return Err(meta.error(format!("Redact serde for `{type_name}` repeats `{name}`",)));
    }
    *output = Some(meta.value()?.parse()?);
    Ok(())
}

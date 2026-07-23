// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Field-scoped capability assertions for generated implementations.

use proc_macro2::TokenStream;
use quote::{
    format_ident,
    quote_spanned,
};
use syn::{
    Field,
    Ident,
    Path,
    spanned::Spanned,
};

use crate::field_mode::FieldMode;

/// Generates the immutable capability assertion for one field.
///
/// The helper name carries the owning type, field, and required trait so that
/// rustc trait-bound diagnostics retain actionable domain context.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated `Redact` implementation.
/// * `field` - Source field supplying the diagnostic span.
/// * `field_name` - Field name or positional index included in the helper name.
/// * `mode` - Explicit redaction mode selecting the required capability.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// A zero-cost local assertion, or no tokens for plain and skipped fields.
pub(crate) fn immutable(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    mode: &FieldMode,
    runtime: &Path,
) -> TokenStream {
    let helper =
        helper_name(type_name, field, field_name, mode.immutable_trait_name());
    match mode {
        FieldMode::Plain | FieldMode::Skip => TokenStream::new(),
        FieldMode::Level(sensitivity) => {
            let level = sensitivity.runtime_tokens(runtime);
            quote_spanned! {field.span()=>
                #[allow(non_snake_case)]
                #[inline(always)]
                fn #helper<'a, __QubitRedactField>(
                    value: &'a __QubitRedactField,
                    policy: &#runtime::RedactionPolicy,
                ) -> #runtime::RedactedValue<'a>
                where
                    __QubitRedactField: #runtime::RedactValue + ?Sized,
                {
                    #runtime::RedactValue::redact_value(
                        value,
                        #level,
                        policy.masking(),
                    )
                }
            }
        }
        FieldMode::Nested => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<'a, __QubitRedactField>(
                value: &'a __QubitRedactField,
                policy: &#runtime::RedactionPolicy,
            ) -> #runtime::Redacted<'a, __QubitRedactField>
            where
                __QubitRedactField: #runtime::Redact,
            {
                #runtime::Redact::redacted_with(value, policy)
            }
        },
        FieldMode::Map => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<
                'a,
                __QubitRedactField,
                __QubitRedactKey: ?Sized,
                __QubitRedactValue: ?Sized,
            >(
                value: &'a __QubitRedactField,
                policy: &#runtime::RedactionPolicy,
            ) -> #runtime::RedactedMap<
                'a,
                __QubitRedactField,
                __QubitRedactKey,
                __QubitRedactValue,
            >
            where
                __QubitRedactField:
                    #runtime::RedactMapValue<
                        __QubitRedactKey,
                        __QubitRedactValue,
                    > + ?Sized,
            {
                #runtime::RedactedMap::new(value, policy.clone())
            }
        },
    }
}

/// Generates the destructive capability assertion for one field.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated `RedactMut` implementation.
/// * `field` - Source field supplying the diagnostic span.
/// * `field_name` - Field name or positional index included in the helper name.
/// * `mode` - Explicit redaction mode selecting the required capability.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// A zero-cost local assertion, or no tokens for plain and skipped fields.
pub(crate) fn mutable(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    mode: &FieldMode,
    runtime: &Path,
) -> TokenStream {
    let helper =
        helper_name(type_name, field, field_name, mode.mutable_trait_name());
    match mode {
        FieldMode::Plain | FieldMode::Skip => TokenStream::new(),
        FieldMode::Level(sensitivity) => {
            let level = sensitivity.runtime_tokens(runtime);
            quote_spanned! {field.span()=>
                #[allow(non_snake_case)]
                #[inline(always)]
                fn #helper<__QubitRedactField>(
                    value: &mut __QubitRedactField,
                    policy: &#runtime::RedactionPolicy,
                )
                where
                    __QubitRedactField: #runtime::RedactValueMut + ?Sized,
                {
                    #runtime::RedactValueMut::redact_value_in_place(
                        value,
                        #level,
                        policy.masking(),
                    );
                }
            }
        }
        FieldMode::Nested => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<__QubitRedactField>(
                value: &mut __QubitRedactField,
                policy: &#runtime::RedactionPolicy,
            )
            where
                __QubitRedactField: #runtime::RedactMut + ?Sized,
            {
                #runtime::RedactMut::redact_in_place_with(value, policy);
            }
        },
        FieldMode::Map => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<
                __QubitRedactField,
                __QubitRedactKey: ?Sized,
                __QubitRedactValue: ?Sized,
            >(
                value: &mut __QubitRedactField,
                policy: &#runtime::RedactionPolicy,
            )
            where
                __QubitRedactField:
                    #runtime::RedactMapValueMut<
                        __QubitRedactKey,
                        __QubitRedactValue,
                    > + ?Sized,
            {
                #runtime::RedactMapValueMut::redact_map_in_place(value, policy);
            }
        },
    }
}

/// Generates the serialization capability assertion for one field.
///
/// # Parameters
///
/// * `type_name` - Type receiving the hidden serialization implementation.
/// * `field` - Source field supplying the diagnostic span.
/// * `field_name` - Field name or positional index included in the helper name.
/// * `mode` - Explicit redaction mode selecting the required capability.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// A zero-cost local assertion for nested and map fields. Other field modes
/// rely on their ordinary serialization expression.
pub(crate) fn serialization(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    mode: &FieldMode,
    runtime: &Path,
) -> TokenStream {
    let helper = helper_name(
        type_name,
        field,
        field_name,
        mode.serialization_trait_name(),
    );
    match mode {
        FieldMode::Nested => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<'a, __QubitRedactField>(
                value: &'a __QubitRedactField,
                policy: &'a #runtime::RedactionPolicy,
            ) -> #runtime::__private::RedactedSerialize<'a, __QubitRedactField>
            where
                __QubitRedactField:
                    #runtime::__private::RedactSerialize + ?Sized,
            {
                #runtime::__private::RedactedSerialize::new(value, policy)
            }
        },
        FieldMode::Map => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<
                'a,
                __QubitRedactField,
                __QubitRedactKey: ?Sized,
                __QubitRedactValue: ?Sized,
            >(
                value: &'a __QubitRedactField,
                policy: &'a #runtime::RedactionPolicy,
            ) -> #runtime::RedactedMap<
                'a,
                __QubitRedactField,
                __QubitRedactKey,
                __QubitRedactValue,
            >
            where
                __QubitRedactField:
                    #runtime::__private::RedactMapSerialize<
                        __QubitRedactKey,
                        __QubitRedactValue,
                    > + ?Sized,
            {
                #runtime::RedactedMap::new(value, policy.clone())
            }
        },
        FieldMode::Plain | FieldMode::Level(_) | FieldMode::Skip => {
            TokenStream::new()
        }
    }
}

/// Creates the stable field-context helper identifier for one capability.
///
/// # Parameters
///
/// * `type_name` - Owning type identifier.
/// * `field` - Source field supplying the identifier span.
/// * `field_name` - Field name or positional index.
/// * `required_trait` - Capability name encoded into the helper identifier.
///
/// # Returns
///
/// A normalized identifier suitable for generated local functions.
pub(crate) fn helper_name(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    required_trait: &str,
) -> Ident {
    let type_fragment = type_name.to_string().replace("r#", "");
    let field_fragment = field_name.replace("r#", "");
    format_ident!(
        "__qubit_redact_{}_{}_requires_{}",
        type_fragment,
        field_fragment,
        required_trait,
        span = field.span(),
    )
}

/// Supplies the immutable trait-name suffix for helper identifiers.
trait ImmutableTraitName {
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

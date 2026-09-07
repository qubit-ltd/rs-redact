// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generated borrowed projections for redacted Serde output.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::DeriveInput;
use syn::Field;
use syn::GenericParam;
use syn::Generics;
use syn::Ident;
use syn::Lifetime;
use syn::LifetimeParam;
use syn::Path;
use syn::Result;
use syn::Type;
use syn::WherePredicate;
use syn::ext::IdentExt;
use syn::parse_quote;
use syn::parse2;
use syn::spanned::Spanned;

use super::r#enum::enum_body;
use super::field::adapter_helper_name;
use super::field::field_context;
use super::r#struct::struct_body;
use crate::attributes::SerdeAttributes;
use crate::attributes::SerdeContainerAttributes;
use crate::expand::assertions;
use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;
use crate::model::VariantData;

/// Generates the lazy Serde projection for every `Redact` derive.
///
/// # Parameters
///
/// * `input` - Source type syntax, visibility, and generic declaration.
/// * `runtime` - Resolved runtime crate path.
/// * `serde` - Serde path, or `None` to emit no serialization tokens.
/// * `container_attributes` - Validated serialization naming and
///   representation.
/// * `model` - Validated source fields and redaction modes.
/// * `generate_serialize` - Whether the source also receives ordinary
///   Serialize.
///
/// # Returns
///
/// Borrowed projection declarations and optionally source serialization
/// implementations.
///
/// # Errors
///
/// Rejects enum field shapes incompatible with the selected Serde
/// representation.
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    serde: Option<&Path>,
    container_attributes: &SerdeContainerAttributes,
    model: &ContainerData<'_>,
    generate_serialize: bool,
) -> Result<TokenStream> {
    let Some(serde) = serde else {
        return Ok(TokenStream::new());
    };
    let name = &input.ident;
    let projection = format_ident!("__QubitRedact{}Fields", name);
    let marker = projection_marker(model);
    let fields = collected_fields(model);
    let parameters = (0..fields.len())
        .map(|index| assertions::fresh_identifier(&input.generics, &format!("__QubitRedactField{index}")))
        .collect::<Vec<_>>();
    let lifetime = assertions::fresh_lifetime(&input.generics);
    let serializer = assertions::fresh_identifier(&input.generics, "__QubitRedactSerializer");
    let adapters = serialization_adapter_helpers(name, &input.generics, model, serde);
    let body = match model {
        ContainerData::Struct(fields) => struct_body(name, fields, runtime, serde, container_attributes),
        ContainerData::Enum(variants) => enum_body(
            name,
            variants,
            runtime,
            serde,
            container_attributes,
            &serializer,
            &marker,
        )?,
    };
    let mut projection_generics = input.generics.clone();
    projection_generics
        .params
        .insert(0, GenericParam::Lifetime(LifetimeParam::new(lifetime.clone())));
    projection_generics.params.extend(
        parameters
            .iter()
            .map(|parameter| -> GenericParam { parse_quote!(#parameter) }),
    );
    let (projection_impl_generics, projection_type_generics, _) = projection_generics.split_for_impl();
    let declaration = projection_declaration(
        input,
        &projection,
        &lifetime,
        &parameters,
        model,
        &projection_generics,
        &marker,
    );
    let constructor = projection_constructor(name, &projection, model, &marker);
    let actual_types = fields.iter().map(|field| &field.ty).collect::<Vec<_>>();
    let projection_bounds = projection_bounds(model, &parameters, runtime, serde, &lifetime);
    let (source_impl_generics, source_type_generics, source_where_clause) = input.generics.split_for_impl();
    let source_predicates = input.generics.where_clause.iter().flat_map(|clause| &clause.predicates);
    let source_arguments = input
        .generics
        .params
        .iter()
        .map(|parameter| match parameter {
            GenericParam::Lifetime(parameter) => {
                let lifetime = &parameter.lifetime;
                quote!(#lifetime)
            }
            GenericParam::Type(parameter) => {
                let name = &parameter.ident;
                quote!(#name)
            }
            GenericParam::Const(parameter) => {
                let name = &parameter.ident;
                quote!(#name)
            }
        })
        .collect::<Vec<_>>();

    let source_serialize = generate_serialize.then(|| {
        let mut generics = input.generics.clone();
        generics
            .make_where_clause()
            .predicates
            .extend(source_bounds(model, runtime, serde).into_iter().map(|bound| {
                parse2::<WherePredicate>(bound).expect("valid source capability bound")
            }));
        let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
        quote! {
            impl #impl_generics #runtime::domain::internal::RedactSerialize for #name #type_generics #where_clause {
                fn serialize_redacted<#serializer>(&self, serializer: #serializer, policy: &#runtime::RedactionPolicy) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #serde::Serializer {
                    let projection: #projection<'_, #(#source_arguments,)* #(#actual_types),*> = #constructor;
                    #serde::Serialize::serialize(&projection, serializer)
                }
            }

            impl #impl_generics #serde::Serialize for #name #type_generics #where_clause {
                fn serialize<#serializer>(&self, serializer: #serializer) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #serde::Serializer {
                    let redactor = #runtime::Redactor::application_default();
                    #serde::Serialize::serialize(&#runtime::domain::internal::RedactedSerializeRef::new(self, redactor.policy()), serializer)
                }
            }
        }
    });
    let required_serialize = source_serialize.map(|tokens| quote!(#runtime::__qubit_redact_serde! { #tokens }));

    Ok(quote! {
        #runtime::__qubit_redact_serde_optional! {
            #declaration

            impl #projection_impl_generics #serde::Serialize for #projection #projection_type_generics
            where #(#source_predicates,)* #(#projection_bounds),* {
                fn serialize<#serializer>(&self, serializer: #serializer) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #serde::Serializer {
                    let policy_owner = #runtime::domain::internal::current_policy()
                        .expect("redacted projections require an active serialization scope");
                    let policy = policy_owner.as_ref();
                    #(#adapters)*
                    #runtime::domain::internal::serialize_structured(serializer, policy_owner.as_ref(), |serializer| { #body })
                }
            }

            impl #source_impl_generics #runtime::domain::internal::RedactSerializeSource
                for #name #source_type_generics #source_where_clause {
                type RedactedFields<#lifetime> = #projection<#lifetime, #(#source_arguments,)* #(#actual_types),*>
                where Self: #lifetime;

                fn redacted_fields<#lifetime>(&#lifetime self, _policy: &#runtime::RedactionPolicy) -> Self::RedactedFields<#lifetime> {
                    #constructor
                }
            }
        }
        #required_serialize
    })
}

/// Collects capability predicates for the borrowed projection.
///
/// # Parameters
///
/// * `model` - Validated struct or enum fields.
/// * `parameters` - One generated type parameter per source field in traversal
///   order.
/// * `runtime` - Resolved runtime crate path.
/// * `serde` - Resolved Serde path.
/// * `lifetime` - Actual borrow lifetime of fields in this projection.
///
/// # Returns
///
/// Projection predicates matching each selected field mode.
///
/// # Panics
///
/// Panics if the generated parameter count does not match the model fields.
#[must_use]
fn projection_bounds(
    model: &ContainerData<'_>,
    parameters: &[Ident],
    runtime: &Path,
    serde: &Path,
    lifetime: &Lifetime,
) -> Vec<TokenStream> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    match model {
        ContainerData::Struct(fields) => {
            projection_group_bounds(fields, parameters, &mut offset, runtime, serde, lifetime, &mut result)
        }
        ContainerData::Enum(variants) => {
            for variant in variants {
                if variant.serde_attributes().skip() {
                    offset += match variant.fields() {
                        FieldsData::Named(fields) => fields.len(),
                        FieldsData::Unnamed(fields) => fields.len(),
                        FieldsData::Unit => 0,
                    };
                    continue;
                }
                projection_group_bounds(
                    variant.fields(),
                    parameters,
                    &mut offset,
                    runtime,
                    serde,
                    lifetime,
                    &mut result,
                );
            }
        }
    }
    result
}

/// Appends capability predicates for one field group.
///
/// # Parameters
///
/// * `fields` - Validated named, tuple, or unit fields.
/// * `parameters` - Generated parameters for every model field.
/// * `offset` - Index of this group, advanced past its fields.
/// * `runtime` - Resolved runtime crate path.
/// * `serde` - Resolved Serde path.
/// * `lifetime` - Borrow lifetime required of nested field projections.
/// * `result` - Destination for generated capability predicates.
///
/// # Panics
///
/// Panics if the parameter slice cannot cover the group at the supplied offset.
fn projection_group_bounds(
    fields: &FieldsData<'_>,
    parameters: &[Ident],
    offset: &mut usize,
    runtime: &Path,
    serde: &Path,
    _lifetime: &Lifetime,
    result: &mut Vec<TokenStream>,
) {
    match fields {
        FieldsData::Named(fields) => {
            for (index, field) in fields.iter().enumerate() {
                if field.serde_attributes().skip() {
                    continue;
                }
                let parameter =
                    projection_field_type(field.field(), field.serde_attributes(), &parameters[*offset + index]);
                match field.attributes().mode() {
                    FieldMode::Unmarked | FieldMode::Skip if field.serde_attributes().serialize_with().is_none() => {
                        result.push(quote!(#parameter: #serde::Serialize))
                    }
                    FieldMode::DisplayLevel(_) => result.push(quote!(#parameter: ::core::fmt::Display)),
                    FieldMode::Level(_) => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize))
                    }
                    FieldMode::KeyedBy(key) => {
                        result.push(
                            quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize + #serde::Serialize),
                        );
                        if let Some(key_index) = fields.iter().position(|item| item.identifier() == key) {
                            let key_field = &fields[key_index];
                            let key_parameter = projection_field_type(
                                key_field.field(),
                                key_field.serde_attributes(),
                                &parameters[*offset + key_index],
                            );
                            result.push(quote!(#key_parameter: ::core::convert::AsRef<str>));
                        }
                    }
                    FieldMode::Nested => result.push(quote!(#parameter: #runtime::domain::internal::RedactSerialize)),
                    FieldMode::Map => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapSerialize)),
                    FieldMode::MapLevels { .. } => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactMapKeySerialize))
                    }
                    FieldMode::Json => result.push(quote!(#parameter: #runtime::domain::internal::RedactJsonSerialize)),
                    _ => {}
                }
            }
            *offset += fields.len();
        }
        FieldsData::Unnamed(fields) => {
            for (index, field) in fields.iter().enumerate() {
                if field.serde_attributes().skip() {
                    continue;
                }
                let parameter =
                    projection_field_type(field.field(), field.serde_attributes(), &parameters[*offset + index]);
                match field.attributes().mode() {
                    FieldMode::Unmarked | FieldMode::Skip if field.serde_attributes().serialize_with().is_none() => {
                        result.push(quote!(#parameter: #serde::Serialize))
                    }
                    FieldMode::DisplayLevel(_) => result.push(quote!(#parameter: ::core::fmt::Display)),
                    FieldMode::Level(_) => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize))
                    }
                    FieldMode::Nested => result.push(quote!(#parameter: #runtime::domain::internal::RedactSerialize)),
                    FieldMode::Map => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapSerialize)),
                    FieldMode::MapLevels { .. } => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactMapKeySerialize))
                    }
                    FieldMode::Json => result.push(quote!(#parameter: #runtime::domain::internal::RedactJsonSerialize)),
                    _ => {}
                }
            }
            *offset += fields.len();
        }
        FieldsData::Unit => {}
    }
}

/// Collects the concrete source-field capabilities required by the generated
/// source implementation. Unlike the borrowed projection path, these bounds
/// do not quantify over an arbitrary source lifetime.
fn source_bounds(model: &ContainerData<'_>, runtime: &Path, serde: &Path) -> Vec<TokenStream> {
    let mut result = Vec::new();
    let mut groups = Vec::new();
    match model {
        ContainerData::Struct(fields) => groups.push(fields),
        ContainerData::Enum(variants) => groups.extend(
            variants
                .iter()
                .filter(|variant| !variant.serde_attributes().skip())
                .map(VariantData::fields),
        ),
    }
    for fields in groups {
        source_group_bounds(fields, runtime, serde, &mut result);
    }
    result
}

/// Appends concrete capability bounds for one source field group.
fn source_group_bounds(fields: &FieldsData<'_>, runtime: &Path, serde: &Path, result: &mut Vec<TokenStream>) {
    match fields {
        FieldsData::Named(fields) => {
            for field in fields {
                source_field_bound(
                    field.field(),
                    field.attributes().mode(),
                    field.serde_attributes(),
                    runtime,
                    serde,
                    result,
                );
            }
        }
        FieldsData::Unnamed(fields) => {
            for field in fields {
                source_field_bound(
                    field.field(),
                    field.attributes().mode(),
                    field.serde_attributes(),
                    runtime,
                    serde,
                    result,
                );
            }
        }
        FieldsData::Unit => {}
    }
}

/// Appends capability bounds for one concrete field.
fn source_field_bound(
    field: &Field,
    mode: &FieldMode,
    serde_attributes: &SerdeAttributes,
    runtime: &Path,
    serde: &Path,
    result: &mut Vec<TokenStream>,
) {
    let ty = &field.ty;
    if serde_attributes.skip() {
        return;
    }
    match mode {
        FieldMode::Unmarked | FieldMode::Skip if serde_attributes.serialize_with().is_none() => {
            if !matches!(field.ty, Type::Reference(_)) {
                result.push(quote!(#ty: #serde::Serialize));
            }
        }
        FieldMode::DisplayLevel(_) => result.push(quote!(#ty: ::core::fmt::Display)),
        FieldMode::Level(_) => result.push(quote!(#ty: #runtime::domain::internal::RedactLevelSerialize)),
        FieldMode::Nested => result.push(quote!(#ty: #runtime::domain::internal::RedactSerialize)),
        FieldMode::Map => result.push(quote!(#ty: #runtime::domain::internal::RedactMapSerialize)),
        FieldMode::MapLevels { .. } => {
            result.push(quote!(#ty: #runtime::domain::internal::RedactMapKeySerialize));
        }
        FieldMode::KeyedBy(_) => {
            result.push(quote!(#ty: #runtime::domain::internal::RedactLevelSerialize + #serde::Serialize));
        }
        FieldMode::Json => result.push(quote!(#ty: #runtime::domain::internal::RedactJsonSerialize)),
        FieldMode::Unmarked | FieldMode::Skip => {}
    }
    if (matches!(mode, FieldMode::Unmarked | FieldMode::Skip) && serde_attributes.skip_serializing_if().is_some())
        && !matches!(field.ty, Type::Reference(_))
    {
        result.push(quote!(#ty: #serde::Serialize));
    }
}

/// Collects source fields in projection parameter order.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the model and its borrowed source syntax.
///
/// # Parameters
///
/// * `model` - Borrowed struct or enum model.
///
/// # Returns
///
/// All source fields in declaration order.
#[must_use]
fn collected_fields<'a>(model: &'a ContainerData<'a>) -> Vec<&'a Field> {
    let mut result = Vec::new();
    match model {
        ContainerData::Struct(fields) => collect_group(fields, &mut result),
        ContainerData::Enum(variants) => {
            for variant in variants {
                collect_group(variant.fields(), &mut result);
            }
        }
    }
    result
}

/// Appends source fields from one field group.
///
/// # Type Parameters
///
/// * `'a` - Lifetime shared by the field model and the collected source
///   references.
///
/// # Parameters
///
/// * `fields` - Borrowed named, tuple, or unit field group.
/// * `result` - Destination for source field references.
fn collect_group<'a>(fields: &'a FieldsData<'a>, result: &mut Vec<&'a Field>) {
    match fields {
        FieldsData::Named(fields) => result.extend(fields.iter().map(|field| field.field())),
        FieldsData::Unnamed(fields) => result.extend(fields.iter().map(|field| field.field())),
        FieldsData::Unit => {}
    }
}

/// Declares the hidden borrowed projection type.
///
/// # Parameters
///
/// * `input` - Source type supplying visibility, generic context, and marker
///   type.
/// * `projection` - Generated projection type identifier.
/// * `lifetime` - Lifetime used by each borrowed field.
/// * `parameters` - Generated type parameters in source-field order.
/// * `model` - Validated source shape.
/// * `generics` - Source and generated projection parameters, including bounds.
/// * `marker` - Fresh member name reserved for the projection lifetime marker.
///
/// # Returns
///
/// A hidden struct or enum declaration with borrowed fields and a lifetime
/// marker.
///
/// # Panics
///
/// Panics if an enum field has no corresponding generated type parameter.
#[must_use]
fn projection_declaration(
    input: &DeriveInput,
    projection: &Ident,
    lifetime: &Lifetime,
    parameters: &[Ident],
    model: &ContainerData<'_>,
    generics: &Generics,
    marker: &Ident,
) -> TokenStream {
    let visibility = &input.vis;
    let source = &input.ident;
    let (_, source_arguments, source_where_clause) = input.generics.split_for_impl();
    let (declaration_generics, _, _) = generics.split_for_impl();
    match model {
        ContainerData::Struct(fields) => {
            let members = match fields {
                FieldsData::Named(fields) => fields
                    .iter()
                    .zip(parameters)
                    .map(|(field, parameter)| {
                        let name = field.identifier();
                        let ty = projection_field_type(field.field(), field.serde_attributes(), parameter);
                        quote!(#name: &#lifetime #ty)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unnamed(fields) => fields
                    .iter()
                    .zip(parameters)
                    .map(|(field, parameter)| {
                        let name = format_ident!("__qubit_redact_field_{}", field.index().index);
                        let ty = projection_field_type(field.field(), field.serde_attributes(), parameter);
                        quote!(#name: &#lifetime #ty)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unit => Vec::new(),
            };
            quote! {
                #[doc(hidden)]
                #[derive(Clone, Copy)]
                #visibility struct #projection #declaration_generics #source_where_clause {
                    #marker: ::core::marker::PhantomData<(&#lifetime #source #source_arguments, #(&#lifetime #parameters),*)>,
                    #(#members),*
                }
            }
        }
        ContainerData::Enum(variants) => {
            let mut offset = 0usize;
            let declarations = variants.iter().map(|variant| {
                let name = &variant.variant().ident;
                let declaration = match variant.fields() {
                    FieldsData::Named(fields) => {
                        let start = offset;
                        let members = fields.iter().enumerate().map(|(index, field)| {
                            let name = field.identifier();
                            let parameter = projection_field_type(
                                field.field(),
                                field.serde_attributes(),
                                &parameters[start + index],
                            );
                            quote!(#name: &#lifetime #parameter)
                        });
                        offset += fields.len();
                        quote!({ #(#members),* })
                    }
                    FieldsData::Unnamed(fields) => {
                        let start = offset;
                        let members = fields.iter().enumerate().map(|(index, field)| {
                            let parameter = projection_field_type(
                                field.field(),
                                field.serde_attributes(),
                                &parameters[start + index],
                            );
                            quote!(&#lifetime #parameter)
                        });
                        offset += fields.len();
                        quote!(( #(#members),* ))
                    }
                    FieldsData::Unit => TokenStream::new(),
                };
                quote!(#name #declaration)
            });
            quote! {
                #[doc(hidden)]
                #[derive(Clone, Copy)]
                #visibility enum #projection #declaration_generics #source_where_clause {
                    #(#declarations,)*
                    #marker(::core::marker::PhantomData<(&#lifetime #source #source_arguments, #(&#lifetime #parameters),*)>)
                }
            }
        }
    }
}

/// Selects the field type visible to predicates and custom serializers.
///
/// # Parameters
///
/// * `field` - Source field retaining its concrete generic type expression.
/// * `attributes` - Serialization controls that may call a type-specific
///   function.
/// * `parameter` - Independent projection parameter for ordinary field
///   capabilities.
///
/// # Returns
///
/// The source type for fields with predicates or adapters, otherwise the
/// generated parameter that keeps serialization bounds conditional.
#[must_use]
fn projection_field_type(field: &Field, attributes: &SerdeAttributes, parameter: &Ident) -> TokenStream {
    if attributes.skip_serializing_if().is_some() || attributes.serialize_with().is_some() {
        let ty = &field.ty;
        quote!(#ty)
    } else {
        quote!(#parameter)
    }
}

/// Builds a borrowed projection from the source value.
///
/// # Parameters
///
/// * `name` - Source type identifier used in enum patterns.
/// * `projection` - Generated projection type identifier.
/// * `model` - Validated source shape and source fields.
/// * `marker` - Fresh member name used by the projection declaration.
///
/// # Returns
///
/// An expression borrowing the struct fields or matching the selected enum
/// variant.
#[must_use]
fn projection_constructor(name: &Ident, projection: &Ident, model: &ContainerData<'_>, marker: &Ident) -> TokenStream {
    match model {
        ContainerData::Struct(fields) => {
            let members = match fields {
                FieldsData::Named(fields) => fields
                    .iter()
                    .map(|field| {
                        let name = field.identifier();
                        quote!(#name: &self.#name)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unnamed(fields) => fields
                    .iter()
                    .map(|field| {
                        let index = field.index();
                        let name = format_ident!("__qubit_redact_field_{}", index.index);
                        quote!(#name: &self.#index)
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unit => Vec::new(),
            };
            quote!(#projection { #marker: ::core::marker::PhantomData, #(#members),* })
        }
        ContainerData::Enum(variants) => {
            if variants.is_empty() {
                return quote!(match *self {});
            }
            let arms = variants.iter().map(|variant| {
                let variant_name = &variant.variant().ident;
                match variant.fields() {
                    FieldsData::Named(fields) => {
                        let names = fields.iter().map(|field| field.identifier()).collect::<Vec<_>>();
                        quote!(#name::#variant_name { #(#names),* } => #projection::#variant_name { #(#names),* })
                    }
                    FieldsData::Unnamed(fields) => {
                        let names = fields
                            .iter()
                            .enumerate()
                            .map(|(index, field)| {
                                format_ident!("__qubit_redact_projection_{index}", span = field.field().span())
                            })
                            .collect::<Vec<_>>();
                        quote!(#name::#variant_name(#(#names),*) => #projection::#variant_name(#(#names),*))
                    }
                    FieldsData::Unit => quote!(#name::#variant_name => #projection::#variant_name),
                }
            });
            quote!(match self { #(#arms),* })
        }
    }
}

/// Collects local Serde carriers for custom field adapters.
///
/// # Parameters
///
/// * `type_name` - Owning type used to name generated helpers.
/// * `generics` - Source generic parameters and bounds.
/// * `model` - Validated source fields and adapter controls.
/// * `serde` - Resolved Serde path.
///
/// # Returns
///
/// Local helper declarations for fields with custom serialization adapters.
#[must_use]
fn serialization_adapter_helpers(
    type_name: &Ident,
    generics: &Generics,
    model: &ContainerData<'_>,
    serde: &Path,
) -> Vec<TokenStream> {
    match model {
        ContainerData::Struct(fields) => helpers_for_group(type_name, generics, fields, None, serde),
        ContainerData::Enum(variants) => variants
            .iter()
            .filter(|variant| !variant.serde_attributes().skip())
            .flat_map(|variant| helpers_for_group(type_name, generics, variant.fields(), Some(variant), serde))
            .collect(),
    }
}

/// Builds custom serialization helpers for one field group.
///
/// # Parameters
///
/// * `type_name` - Owning source type identifier.
/// * `generics` - Source generic parameters and bounds.
/// * `fields` - Fields whose optional adapters are inspected.
/// * `variant` - Owning enum variant, or None for struct fields.
/// * `serde` - Resolved Serde path.
///
/// # Returns
///
/// Helper declarations only for fields with a serialization adapter.
#[must_use]
fn helpers_for_group(
    type_name: &Ident,
    generics: &Generics,
    fields: &FieldsData<'_>,
    variant: Option<&VariantData<'_>>,
    serde: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .filter(|field| !field.serde_attributes().skip())
            .filter_map(|field| {
                adapter_helper(
                    type_name,
                    generics,
                    field.field(),
                    &field_context(
                        variant.map(|item| &item.variant().ident),
                        variant.map(VariantData::index),
                        &field.identifier().to_string(),
                    ),
                    field.serde_attributes().serialize_with(),
                    serde,
                )
            })
            .collect(),
        FieldsData::Unnamed(fields) => fields
            .iter()
            .filter(|field| !field.serde_attributes().skip())
            .filter_map(|field| {
                adapter_helper(
                    type_name,
                    generics,
                    field.field(),
                    &field_context(
                        variant.map(|item| &item.variant().ident),
                        variant.map(VariantData::index),
                        &field.index().index.to_string(),
                    ),
                    field.serde_attributes().serialize_with(),
                    serde,
                )
            })
            .collect(),
        FieldsData::Unit => Vec::new(),
    }
}

/// Builds a local borrowing carrier for one custom adapter.
///
/// # Parameters
///
/// * `type_name` - Owning type used to name the carrier.
/// * `generics` - Source generic parameters used by the field.
/// * `field` - Source field supplying its type and diagnostic span.
/// * `context` - Stable field context used in helper names.
/// * `adapter` - Custom serialization function, or None to use ordinary Serde.
/// * `serde` - Resolved Serde path.
///
/// # Returns
///
/// Some carrier and helper declarations when an adapter exists, otherwise None.
#[must_use]
fn adapter_helper(
    type_name: &Ident,
    generics: &Generics,
    field: &Field,
    context: &str,
    adapter: Option<&Path>,
    serde: &Path,
) -> Option<TokenStream> {
    let adapter = adapter?;
    let helper = adapter_helper_name(type_name, field, context);
    let wrapper = format_ident!("{helper}_carrier", span = field.span());
    let field_type = &field.ty;
    let lifetime = assertions::fresh_lifetime(generics);
    let mut helper_generics = assertions::generics_for_field(generics, field_type);
    helper_generics
        .params
        .insert(0, GenericParam::Lifetime(LifetimeParam::new(lifetime.clone())));
    let serializer = assertions::fresh_identifier(&helper_generics, "__QubitRedactSerializer");
    let marker_types = helper_generics.params.iter().filter_map(|parameter| match parameter {
        GenericParam::Lifetime(parameter) => {
            let lifetime = &parameter.lifetime;
            Some(quote!(&#lifetime ()))
        }
        GenericParam::Type(parameter) => {
            let name = &parameter.ident;
            Some(quote!(*const #name))
        }
        GenericParam::Const(_) => None,
    });
    let params = &helper_generics.params;
    let (impl_generics, type_generics, where_clause) = helper_generics.split_for_impl();
    Some(quote_spanned! {field.span()=>
        #[allow(non_camel_case_types)] struct #wrapper<#params>(&#lifetime #field_type, ::core::marker::PhantomData<(#(#marker_types,)*)>) #where_clause;
        impl #impl_generics #serde::Serialize for #wrapper #type_generics #where_clause { fn serialize<#serializer>(&self, serializer: #serializer) -> ::core::result::Result<#serializer::Ok, #serializer::Error> where #serializer: #serde::Serializer { #adapter(self.0, serializer) } }
        #[allow(non_snake_case)] let #helper = |value: &#lifetime #field_type| -> #wrapper #type_generics { #wrapper(value, ::core::marker::PhantomData) };
    })
}

/// Chooses a projection marker distinct from source field or variant names.
///
/// # Parameters
///
/// * `model` - Source members occupying the generated projection namespace.
///
/// # Returns
///
/// A fresh marker identifier, comparing raw and ordinary spellings equally.
///
/// # Panics
///
/// Panics only if every generated numeric suffix is occupied.
#[must_use]
fn projection_marker(model: &ContainerData<'_>) -> Ident {
    let (base, occupied) = match model {
        ContainerData::Struct(FieldsData::Named(fields)) => (
            "__qubit_redact_lifetime",
            fields
                .iter()
                .map(|field| field.identifier().unraw().to_string())
                .collect::<Vec<_>>(),
        ),
        ContainerData::Struct(_) => ("__qubit_redact_lifetime", Vec::new()),
        ContainerData::Enum(variants) => (
            "__QubitRedactLifetime",
            variants
                .iter()
                .map(|variant| variant.variant().ident.unraw().to_string())
                .collect(),
        ),
    };
    if !occupied.iter().any(|name| name == base) {
        return format_ident!("{base}");
    }
    (0..)
        .map(|index| format_ident!("{base}_{index}"))
        .find(|candidate| !occupied.contains(&candidate.to_string()))
        .expect("a finite source has an unused projection marker name")
}

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
use syn::DeriveInput;
use syn::Field;
use syn::GenericParam;
use syn::Ident;
use syn::LifetimeParam;
use syn::Path;
use syn::Result;
use syn::WherePredicate;
use syn::parse_quote;
use syn::parse2;

use super::r#enum::enum_body;
use super::internal::rebind_source_generics;
use super::recursive_projection;
use super::source_function_path::SourceTypeContext;
use super::r#struct::struct_body;
use crate::attributes::SerdeContainerAttributes;
use crate::expand::assertions;
use crate::model::ContainerData;
use crate::model::FieldsData;

// Generates distinct capability bounds for borrowed and source serialization.
mod bounds;
// Generates local carriers for custom serialization adapters.
mod adapters;
// Generates borrowed projection declarations and construction expressions.
mod projection;

use self::adapters::serialization_adapter_helpers;
use self::bounds::projection_bounds;
use self::bounds::source_bounds;
use self::projection::projection_declaration;
use self::projection::projection_marker;

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
    let source_context = SourceTypeContext {
        ident: name,
        generics: &input.generics,
    };
    let unsupported_recursive_fields = recursive_projection::has_unsupported_recursive_field(input, model);
    let recursive_target = if unsupported_recursive_fields {
        String::new()
    } else {
        assertions::recursive_target(input)
    };
    let name_fragment = name.to_string();
    let name_fragment = name_fragment.trim_start_matches("r#");
    let projection = format_ident!("__QubitRedact{}Fields", name);
    let source_projection =
        assertions::fresh_identifier(&input.generics, &format!("__QubitRedact{name_fragment}Projection"));
    let source_fields_trait =
        assertions::fresh_identifier(&input.generics, &format!("__QubitRedact{name_fragment}SourceFields"));
    let marker = projection_marker(model);
    let fields = collected_fields(model);
    let parameters = (0..fields.len())
        .map(|index| assertions::fresh_identifier(&input.generics, &format!("__QubitRedactField{index}")))
        .collect::<Vec<_>>();
    let lifetime = assertions::fresh_lifetime(&input.generics);
    let source_lifetime = assertions::fresh_lifetime(&input.generics);
    let source_parameter = assertions::fresh_identifier(&input.generics, "__QubitRedactSource");
    let source_serializer = assertions::fresh_identifier(&input.generics, "__QubitRedactSourceSerializer");
    let serializer = assertions::fresh_identifier(&input.generics, "__QubitRedactSerializer");
    let body = match model {
        ContainerData::Struct(fields) => struct_body(
            &source_context,
            &recursive_target,
            fields,
            runtime,
            serde,
            container_attributes,
            false,
        ),
        ContainerData::Enum(variants) => enum_body(
            &source_context,
            &recursive_target,
            variants,
            runtime,
            serde,
            container_attributes,
            &serializer,
            &marker,
            false,
        )?,
    };
    let legacy_body = if generate_serialize {
        Some(match model {
            ContainerData::Struct(fields) => struct_body(
                &source_context,
                &recursive_target,
                fields,
                runtime,
                serde,
                container_attributes,
                true,
            ),
            ContainerData::Enum(variants) => enum_body(
                &source_context,
                &recursive_target,
                variants,
                runtime,
                serde,
                container_attributes,
                &serializer,
                &marker,
                true,
            )?,
        })
    } else {
        None
    };
    let rebound_source_generics = rebind_source_generics(name, &input.generics);
    let mut projection_generics = rebound_source_generics.clone();
    projection_generics
        .params
        .insert(0, GenericParam::Lifetime(LifetimeParam::new(lifetime.clone())));
    projection_generics.params.extend(
        parameters
            .iter()
            .map(|parameter| -> GenericParam { parse_quote!(#parameter: ?Sized) }),
    );
    let adapters = serialization_adapter_helpers(
        &source_context,
        &rebound_source_generics,
        &projection_generics,
        model,
        serde,
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
    let recursive_helpers = recursive_projection::expand(input, &projection, model, &marker, runtime, serde);
    let actual_types = fields.iter().map(|field| &field.ty).collect::<Vec<_>>();
    let projection_bounds = projection_bounds(input, model, &parameters, runtime, serde, &lifetime);
    let recursive_source_bounds = if recursive_projection::supports_recursive_projection(input, model) {
        source_bounds(model, runtime, serde)
            .into_iter()
            .flat_map(|bound| {
                assertions::non_recursive_predicates(
                    input,
                    parse2::<WherePredicate>(bound).expect("valid source capability bound"),
                )
                .into_iter()
                .map(|predicate| quote!(#predicate))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let (source_impl_generics, source_type_generics, source_where_clause) = input.generics.split_for_impl();
    let source_predicates = projection_generics
        .where_clause
        .iter()
        .flat_map(|clause| &clause.predicates);
    let projection_serialize_impl = (!unsupported_recursive_fields).then(|| {
        quote! {
            impl #projection_impl_generics #serde::Serialize for #projection #projection_type_generics
            where #(#source_predicates,)* #(#projection_bounds,)* #(#recursive_source_bounds),* {
                fn serialize<#serializer>(&self, serializer: #serializer) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #serde::Serializer {
                    let policy_owner = #runtime::domain::internal::current_policy()
                        .ok_or_else(|| {
                            <#serializer::Error as #serde::ser::Error>::custom(
                                "serialization requires an active redaction scope",
                            )
                        })?;
                    let policy = policy_owner.as_ref();
                    #(#adapters)*
                    #runtime::domain::internal::serialize_structured(serializer, policy_owner.as_ref(), |serializer| { #body })
                }
            }
        }
    });
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
    let source_projection_type = quote!(#projection<#source_lifetime, #(#source_arguments,)* #(#actual_types),*>);
    let projection_constructor = projection_constructor_for(&source_context, &projection, model, &marker, quote!(self));
    let source_projection_visibility = &input.vis;
    let source_projection_support = quote! {
        trait #source_fields_trait {
            type Fields<#source_lifetime>
            where
                Self: #source_lifetime;

            fn project<#source_lifetime>(&#source_lifetime self) -> Self::Fields<#source_lifetime>;
        }

        impl #source_impl_generics #source_fields_trait for #name #source_type_generics #source_where_clause {
            type Fields<#source_lifetime> = #source_projection_type
            where
                Self: #source_lifetime;

            fn project<#source_lifetime>(&#source_lifetime self) -> Self::Fields<#source_lifetime> {
                #projection_constructor
            }
        }

        #[doc(hidden)]
        #source_projection_visibility struct #source_projection<#source_lifetime, #source_parameter: ?Sized> {
            source: &#source_lifetime #source_parameter,
        }

        #[allow(private_bounds)]
        impl<#source_lifetime, #source_parameter: ?Sized> #serde::Serialize
            for #source_projection<#source_lifetime, #source_parameter>
        where
            #source_parameter: #source_fields_trait + #source_lifetime,
            <#source_parameter as #source_fields_trait>::Fields<#source_lifetime>: #serde::Serialize,
        {
            fn serialize<#source_serializer>(&self, serializer: #source_serializer)
                -> ::core::result::Result<#source_serializer::Ok, #source_serializer::Error>
            where
                #source_serializer: #serde::Serializer,
            {
                #serde::Serialize::serialize(
                    &<#source_parameter as #source_fields_trait>::project(self.source),
                    serializer,
                )
            }
        }
    };

    let source_serialize = generate_serialize.then(|| {
        let legacy_body = legacy_body.as_ref().expect("legacy body generated for source Serialize");
        let mut generics = input.generics.clone();
        generics
            .make_where_clause()
            .predicates
            .extend(source_bounds(model, runtime, serde).into_iter().flat_map(|bound| {
                crate::expand::assertions::non_recursive_predicates(input, parse2::<WherePredicate>(bound).expect("valid source capability bound"))
            }));
        let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
        quote! {
            impl #impl_generics #runtime::domain::internal::RedactSerialize for #name #type_generics #where_clause {
                fn serialize_redacted<#serializer>(&self, serializer: #serializer, policy: &#runtime::RedactionPolicy) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #serde::Serializer {
                    #(#adapters)*
                    #runtime::domain::internal::serialize_structured(serializer, policy, |serializer| {
                        #legacy_body
                    })
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
            #recursive_helpers
            #source_projection_support

            #projection_serialize_impl

            impl #source_impl_generics #runtime::domain::internal::RedactSerializeSource
                for #name #source_type_generics #source_where_clause {
                type RedactedFields<#lifetime> = #source_projection<#lifetime, Self>
                where Self: #lifetime;

                fn redacted_fields<#lifetime>(&#lifetime self, _policy: &#runtime::RedactionPolicy) -> Self::RedactedFields<#lifetime> {
                    #source_projection { source: self }
                }
            }
        }
        #required_serialize
    })
}

/// Builds a borrowed projection from the source value.
///
/// # Parameters
///
/// * `source_context` - Source identity for enum patterns and saved predicates.
/// * `projection` - Generated projection type identifier.
/// * `model` - Validated source shape and source fields.
/// * `marker` - Fresh member name used by the projection declaration.
///
/// # Returns
///
/// An expression borrowing the struct fields or matching the selected enum
/// variant.
#[must_use]
pub(super) fn projection_constructor_for(
    source_context: &SourceTypeContext<'_>,
    projection: &Ident,
    model: &ContainerData<'_>,
    marker: &Ident,
    source: TokenStream,
) -> TokenStream {
    projection::projection_constructor_for(source_context, projection, model, marker, source)
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

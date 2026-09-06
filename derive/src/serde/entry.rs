// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
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
use syn::Visibility;
use syn::spanned::Spanned;

use super::r#enum::enum_body;
use super::field::adapter_helper_name;
use super::field::field_context;
use super::r#struct::struct_body;
use crate::attributes::SerdeContainerAttributes;
use crate::expand::assertions;
use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;
use crate::model::VariantData;

/// Generates the lazy Serde projection for every `Redact` derive.
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
    let fields = collected_fields(model);
    let parameters = (0..fields.len())
        .map(|index| format_ident!("__QubitRedactField{index}"))
        .collect::<Vec<_>>();
    let lifetime = Lifetime::new("'__qubit_redact", name.span());
    let serializer = assertions::fresh_identifier(&input.generics, "__QubitRedactSerializer");
    let adapters = serialization_adapter_helpers(name, &input.generics, model, serde);
    let body = match model {
        ContainerData::Struct(fields) => struct_body(name, fields, runtime, serde, container_attributes),
        ContainerData::Enum(variants) => enum_body(name, variants, runtime, serde, container_attributes, &serializer)?,
    };
    let declaration = projection_declaration(&input.vis, &projection, &lifetime, &parameters, model, runtime);
    let constructor = projection_constructor(name, &projection, model);
    let actual_types = fields.iter().map(|field| &field.ty);
    let projection_bounds = projection_bounds(model, &parameters, runtime, serde);
    let (source_impl_generics, source_type_generics, source_where_clause) = input.generics.split_for_impl();

    let source_serialize = generate_serialize.then(|| {
        let mut generics = input.generics.clone();
        assertions::add_serialization_bounds(&mut generics, model, runtime, serde);
        let (impl_generics, type_generics, where_clause) = generics.split_for_impl();
        quote! {
            impl #impl_generics #runtime::domain::internal::RedactSerialize for #name #type_generics #where_clause {
                fn serialize_redacted<#serializer>(&self, serializer: #serializer, policy: &#runtime::RedactionPolicy) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #serde::Serializer {
                    #serde::Serialize::serialize(&#runtime::domain::internal::RedactedProjectionRef::new(self, policy), serializer)
                }
            }

            impl #impl_generics #serde::Serialize for #name #type_generics #where_clause {
                fn serialize<#serializer>(&self, serializer: #serializer) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where #serializer: #serde::Serializer {
                    let redactor = #runtime::Redactor::application_default();
                    #serde::Serialize::serialize(&#runtime::domain::internal::RedactedProjectionRef::new(self, redactor.policy()), serializer)
                }
            }
        }
    });
    let required_serialize = source_serialize.map(|tokens| quote!(#runtime::__qubit_redact_serde! { #tokens }));

    Ok(quote! {
        #runtime::__qubit_redact_serde_optional! {
            #declaration

            impl<#lifetime, #(#parameters),*> #serde::Serialize for #projection<#lifetime, #(#parameters),*>
            where #(#projection_bounds),* {
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
                type RedactedFields<#lifetime> = #projection<#lifetime, #(#actual_types),*>
                where Self: #lifetime;

                fn redacted_fields<#lifetime, '__qubit_redact_policy>(&#lifetime self, _policy: &'__qubit_redact_policy #runtime::RedactionPolicy) -> Self::RedactedFields<#lifetime> {
                    #constructor
                }
            }
        }
        #required_serialize
    })
}

fn projection_bounds(
    model: &ContainerData<'_>,
    parameters: &[Ident],
    runtime: &Path,
    serde: &Path,
) -> Vec<TokenStream> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    match model {
        ContainerData::Struct(fields) => {
            projection_group_bounds(fields, parameters, &mut offset, runtime, serde, &mut result)
        }
        ContainerData::Enum(variants) => {
            for variant in variants {
                projection_group_bounds(variant.fields(), parameters, &mut offset, runtime, serde, &mut result);
            }
        }
    }
    result
}

fn projection_group_bounds(
    fields: &FieldsData<'_>,
    parameters: &[Ident],
    offset: &mut usize,
    runtime: &Path,
    serde: &Path,
    result: &mut Vec<TokenStream>,
) {
    match fields {
        FieldsData::Named(fields) => {
            for (index, field) in fields.iter().enumerate() {
                let parameter = &parameters[*offset + index];
                match field.attributes().mode() {
                    FieldMode::Unmarked | FieldMode::Skip if field.serde_attributes().serialize_with().is_none() => result.push(quote!(#parameter: #serde::Serialize)),
                    FieldMode::DisplayLevel(_) => result.push(quote!(#parameter: ::core::fmt::Display)),
                    FieldMode::Level(_) => result.push(quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize)),
                    FieldMode::KeyedBy(key) => {
                        result.push(quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize + #serde::Serialize));
                        if let Some(key_index) = fields.iter().position(|item| item.identifier() == key) {
                            let key_parameter = &parameters[*offset + key_index];
                            result.push(quote!(#key_parameter: ::core::convert::AsRef<str>));
                        }
                    }
                    FieldMode::Nested => result.push(quote!(#parameter: #runtime::domain::internal::RedactSerializeSource, for<'a> <#parameter as #runtime::domain::internal::RedactSerializeSource>::RedactedFields<'a>: #serde::Serialize)),
                    FieldMode::Map => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapSerialize)),
                    FieldMode::MapLevels { .. } => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapKeySerialize)),
                    FieldMode::Json => result.push(quote!(#parameter: #runtime::domain::internal::RedactJsonSerialize)),
                    _ => {}
                }
            }
            *offset += fields.len();
        }
        FieldsData::Unnamed(fields) => {
            for (index, field) in fields.iter().enumerate() {
                let parameter = &parameters[*offset + index];
                match field.attributes().mode() {
                    FieldMode::Unmarked | FieldMode::Skip if field.serde_attributes().serialize_with().is_none() => result.push(quote!(#parameter: #serde::Serialize)),
                    FieldMode::DisplayLevel(_) => result.push(quote!(#parameter: ::core::fmt::Display)),
                    FieldMode::Level(_) => result.push(quote!(#parameter: #runtime::domain::internal::RedactLevelSerialize)),
                    FieldMode::Nested => result.push(quote!(#parameter: #runtime::domain::internal::RedactSerializeSource, for<'a> <#parameter as #runtime::domain::internal::RedactSerializeSource>::RedactedFields<'a>: #serde::Serialize)),
                    FieldMode::Map => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapSerialize)),
                    FieldMode::MapLevels { .. } => result.push(quote!(#parameter: #runtime::domain::internal::RedactMapKeySerialize)),
                    FieldMode::Json => result.push(quote!(#parameter: #runtime::domain::internal::RedactJsonSerialize)),
                    _ => {}
                }
            }
            *offset += fields.len();
        }
        FieldsData::Unit => {}
    }
}

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

fn collect_group<'a>(fields: &'a FieldsData<'a>, result: &mut Vec<&'a Field>) {
    match fields {
        FieldsData::Named(fields) => result.extend(fields.iter().map(|field| field.field())),
        FieldsData::Unnamed(fields) => result.extend(fields.iter().map(|field| field.field())),
        FieldsData::Unit => {}
    }
}

fn projection_declaration(
    visibility: &Visibility,
    projection: &Ident,
    lifetime: &Lifetime,
    parameters: &[Ident],
    model: &ContainerData<'_>,
    _runtime: &Path,
) -> TokenStream {
    match model {
        ContainerData::Struct(fields) => {
            let members = match fields {
                FieldsData::Named(fields) => fields
                    .iter()
                    .zip(parameters)
                    .map(|(field, parameter)| {
                        let name = field.identifier();
                        if field.serde_attributes().skip_serializing_if().is_some()
                            || field.serde_attributes().serialize_with().is_some()
                        {
                            let ty = &field.field().ty;
                            quote!(#name: &#lifetime #ty)
                        } else {
                            quote!(#name: &#lifetime #parameter)
                        }
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unnamed(fields) => fields
                    .iter()
                    .zip(parameters)
                    .map(|(field, parameter)| {
                        let name = format_ident!("__qubit_redact_field_{}", field.index().index);
                        if field.serde_attributes().skip_serializing_if().is_some()
                            || field.serde_attributes().serialize_with().is_some()
                        {
                            let ty = &field.field().ty;
                            quote!(#name: &#lifetime #ty)
                        } else {
                            quote!(#name: &#lifetime #parameter)
                        }
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unit => Vec::new(),
            };
            quote! {
                #[doc(hidden)]
                #[derive(Clone, Copy)]
                #visibility struct #projection<#lifetime, #(#parameters),*> {
                    __qubit_redact_lifetime: ::core::marker::PhantomData<(&#lifetime (), #(&#lifetime #parameters),*)>,
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
                            let parameter = &parameters[start + index];
                            quote!(#name: &#lifetime #parameter)
                        });
                        offset += fields.len();
                        quote!({ #(#members),* })
                    }
                    FieldsData::Unnamed(fields) => {
                        let start = offset;
                        let members = fields.iter().enumerate().map(|(index, _)| {
                            let parameter = &parameters[start + index];
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
                #visibility enum #projection<#lifetime, #(#parameters),*> {
                    #(#declarations),*,
                    __QubitRedactLifetime(::core::marker::PhantomData<(&#lifetime (), #(&#lifetime #parameters),*)>)
                }
            }
        }
    }
}

fn projection_constructor(name: &Ident, projection: &Ident, model: &ContainerData<'_>) -> TokenStream {
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
            quote!(#projection { __qubit_redact_lifetime: ::core::marker::PhantomData, #(#members),* })
        }
        ContainerData::Enum(variants) => {
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
            .flat_map(|variant| helpers_for_group(type_name, generics, variant.fields(), Some(variant), serde))
            .collect(),
    }
}

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
    let params = &helper_generics.params;
    let (impl_generics, type_generics, where_clause) = helper_generics.split_for_impl();
    Some(quote_spanned! {field.span()=>
        #[allow(non_camel_case_types)] struct #wrapper<#params>(&#lifetime #field_type) #where_clause;
        impl #impl_generics #serde::Serialize for #wrapper #type_generics #where_clause { fn serialize<#serializer>(&self, serializer: #serializer) -> ::core::result::Result<#serializer::Ok, #serializer::Error> where #serializer: #serde::Serializer { #adapter(self.0, serializer) } }
        #[allow(non_snake_case)] #[inline(always)] fn #helper #impl_generics(value: &#lifetime #field_type) -> #wrapper #type_generics { #wrapper(value) }
    })
}

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::DeriveInput;
use syn::Field;
use syn::GenericParam;
use syn::Generics;
use syn::Ident;
use syn::LifetimeParam;
use syn::Path;
use syn::Result;
use syn::spanned::Spanned;

use super::r#enum::enum_body;
use super::field::adapter_helper_name;
use super::field::field_context;
use super::r#struct::struct_body;
use crate::attributes::SerdeContainerAttributes;
use crate::expand::assertions;
use crate::model::ContainerData;
use crate::model::FieldsData;
use crate::model::VariantData;

pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    serde: Option<&Path>,
    container_attributes: &SerdeContainerAttributes,
    model: &ContainerData<'_>,
) -> Result<TokenStream> {
    let Some(serde) = serde else {
        return Ok(TokenStream::new());
    };

    let serializer = assertions::fresh_identifier(&input.generics, "__QubitRedactSerializer");
    let mut serialization_generics = input.generics.clone();
    assertions::add_serialization_bounds(&mut serialization_generics, model, runtime, serde);
    let name = &input.ident;
    let adapter_helpers = serialization_adapter_helpers(name, &input.generics, model, serde);
    let (impl_generics, type_generics, where_clause) = serialization_generics.split_for_impl();
    let body = match model {
        ContainerData::Struct(fields) => struct_body(name, fields, runtime, serde, container_attributes),
        ContainerData::Enum(variants) => enum_body(name, variants, runtime, serde, container_attributes, &serializer)?,
    };

    Ok(quote! {
        #runtime::__qubit_redact_serde! {
            impl #impl_generics #runtime::domain::internal::RedactSerialize
                for #name #type_generics #where_clause
            {
                fn serialize_redacted<#serializer>(
                    &self,
                    serializer: #serializer,
                    policy: &#runtime::RedactionPolicy,
                ) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where
                    #serializer: #serde::Serializer,
                {
                    #(#adapter_helpers)*
                    #runtime::domain::internal::serialize_structured(
                        serializer,
                        policy,
                        |serializer| {
                            #body
                        },
                    )
                }
            }

            impl #impl_generics #serde::Serialize
                for #name #type_generics #where_clause
            {
                fn serialize<#serializer>(
                    &self,
                    serializer: #serializer,
                ) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where
                    #serializer: #serde::Serializer,
                {
                    let redactor = #runtime::Redactor::application_default();
                    let policy = redactor.policy();
                    let _scope = #runtime::domain::internal::RedactSerializeScope::new(policy);
                    <Self as #runtime::domain::internal::RedactSerialize>::serialize_redacted(
                        self, serializer, policy,
                    )
                }
            }
        }
    })
}

/// Generates local Serde adapter carriers for unmarked and skipped fields.
fn serialization_adapter_helpers(
    type_name: &Ident,
    generics: &Generics,
    model: &ContainerData<'_>,
    serde: &Path,
) -> Vec<TokenStream> {
    match model {
        ContainerData::Struct(fields) => fields_adapter_helpers(type_name, generics, fields, None, serde),
        ContainerData::Enum(variants) => variants
            .iter()
            .flat_map(|variant| fields_adapter_helpers(type_name, generics, variant.fields(), Some(variant), serde))
            .collect(),
    }
}

/// Generates local Serde adapter carriers for one field collection.
fn fields_adapter_helpers(
    type_name: &Ident,
    generics: &Generics,
    fields: &FieldsData<'_>,
    variant: Option<&VariantData<'_>>,
    serde: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .filter_map(|parsed| {
                let field_name = parsed.identifier().to_string();
                let context = field_context(
                    variant.map(|item| &item.variant().ident),
                    variant.map(VariantData::index),
                    &field_name,
                );
                serialization_adapter_helper(
                    type_name,
                    generics,
                    parsed.field(),
                    &context,
                    parsed.serde_attributes().serialize_with(),
                    serde,
                )
            })
            .collect(),
        FieldsData::Unnamed(fields) => fields
            .iter()
            .filter_map(|parsed| {
                let field_name = parsed.index().index.to_string();
                let context = field_context(
                    variant.map(|item| &item.variant().ident),
                    variant.map(VariantData::index),
                    &field_name,
                );
                serialization_adapter_helper(
                    type_name,
                    generics,
                    parsed.field(),
                    &context,
                    parsed.serde_attributes().serialize_with(),
                    serde,
                )
            })
            .collect(),
        FieldsData::Unit => Vec::new(),
    }
}

/// Generates one local wrapper that invokes a Serde field adapter.
fn serialization_adapter_helper(
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
    let carrier_lifetime = assertions::fresh_lifetime(generics);
    let mut carrier_generics = assertions::generics_for_field(generics, field_type);
    carrier_generics
        .params
        .insert(0, GenericParam::Lifetime(LifetimeParam::new(carrier_lifetime.clone())));
    let serializer = assertions::fresh_identifier(&carrier_generics, "__QubitRedactSerializer");
    let carrier_params = &carrier_generics.params;
    let (impl_generics, type_generics, where_clause) = carrier_generics.split_for_impl();
    Some(quote_spanned! {field.span()=>
        #[allow(non_camel_case_types)]
        struct #wrapper<#carrier_params>(&#carrier_lifetime #field_type) #where_clause;

        impl #impl_generics #serde::Serialize for #wrapper #type_generics #where_clause {
            fn serialize<#serializer>(
                &self,
                serializer: #serializer,
            ) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
            where
                #serializer: #serde::Serializer,
            {
                #adapter(self.0, serializer)
            }
        }

        #[allow(non_snake_case)]
        #[inline(always)]
        fn #helper #impl_generics(
            value: &#carrier_lifetime #field_type,
        ) -> #wrapper #type_generics {
            #wrapper(value)
        }
    })
}

// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Parsing of derive input into the internal container model.

use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Fields;
use syn::Ident;
use syn::Result;

use super::ContainerData;
use super::FieldsData;
use super::VariantData;
use super::named_fields;
use super::unnamed_fields;
use crate::attributes::SerdeVariantAttributes;

pub(crate) fn parse<'a>(input: &'a DeriveInput, derive_name: &str, serde_enabled: bool) -> Result<ContainerData<'a>> {
    match &input.data {
        Data::Struct(data) => Ok(ContainerData::Struct(parse_fields(
            &data.fields,
            &input.ident,
            serde_enabled,
        )?)),
        Data::Enum(data) => {
            let variants = data
                .variants
                .iter()
                .enumerate()
                .map(|(index, variant)| {
                    let serde_attributes = SerdeVariantAttributes::parse(variant, &input.ident, serde_enabled)?;
                    let fields = parse_fields(&variant.fields, &input.ident, serde_enabled)?;
                    Ok(VariantData::new(variant, index as u32, fields, serde_attributes))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(ContainerData::Enum(variants))
        }
        Data::Union(_) => Err(Error::new_spanned(
            input,
            format!("{derive_name} cannot be derived for unions"),
        )),
    }
}

fn parse_fields<'a>(fields: &'a Fields, type_name: &Ident, serde_enabled: bool) -> Result<FieldsData<'a>> {
    match fields {
        Fields::Named(fields) => Ok(FieldsData::Named(named_fields::parse(
            fields,
            type_name,
            serde_enabled,
        )?)),
        Fields::Unnamed(fields) => Ok(FieldsData::Unnamed(unnamed_fields::parse(
            fields,
            type_name,
            serde_enabled,
        )?)),
        Fields::Unit => Ok(FieldsData::Unit),
    }
}

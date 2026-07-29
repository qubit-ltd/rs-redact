// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private derive expansion data structures.

mod container_data;
/// Shared Cargo-aware path mapping for generated derive code.
pub(crate) mod crate_path;
mod fields_data;
mod named_field;
mod serde_container_attribute_parser;
mod unnamed_field;
mod variant_data;

pub(crate) use container_data::ContainerData;
pub(crate) use fields_data::FieldsData;
pub(crate) use named_field::NamedField;
pub(crate) use serde_container_attribute_parser::SerdeContainerAttributeParser;
pub(crate) use unnamed_field::UnnamedField;
pub(crate) use variant_data::VariantData;

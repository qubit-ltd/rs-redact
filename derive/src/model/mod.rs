// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Single parsing boundary for all supported derive input shapes.

mod container_data;
mod field_mode;
mod fields_data;
mod named_field;
mod named_fields;
mod parser;
mod sensitivity;
mod unnamed_field;
mod unnamed_fields;
mod variant_data;

pub(crate) use container_data::ContainerData;
pub(crate) use field_mode::FieldMode;
pub(crate) use fields_data::FieldsData;
pub(crate) use named_field::NamedField;
pub(crate) use parser::parse;
pub(crate) use sensitivity::Sensitivity;
pub(crate) use unnamed_field::UnnamedField;
pub(crate) use variant_data::VariantData;

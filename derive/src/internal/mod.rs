// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private derive expansion data structures.

mod container_data;
mod fields_data;
mod named_field;
mod unnamed_field;
mod variant_data;

pub(crate) use container_data::ContainerData;
pub(crate) use fields_data::FieldsData;
pub(crate) use named_field::NamedField;
pub(crate) use unnamed_field::UnnamedField;
pub(crate) use variant_data::VariantData;

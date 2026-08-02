// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parser-neutral URI component helpers.

mod percent_encoded_field_name;

pub use percent_encoded_field_name::decode_percent_encoded_field_name;

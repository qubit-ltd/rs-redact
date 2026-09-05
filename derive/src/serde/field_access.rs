// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Source expressions used to build one serialized field carrier.

use proc_macro2::TokenStream;

/// Source expressions used by one serialized field carrier.
pub(super) struct FieldAccess {
    /// Expression accessing the unredacted field value.
    pub(super) raw: TokenStream,
    /// Expression accessing the sibling key for keyed fields.
    pub(super) key_raw: Option<TokenStream>,
}

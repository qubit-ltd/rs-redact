// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0 (the "License");
// =============================================================================
//! Macro-time data describing one serialized field.

use proc_macro2::TokenStream;
use syn::Ident;

/// Prepared carrier setup and event metadata for one serialized field.
pub(in crate::serde) struct SerializedFieldPlan {
    /// Tokens which evaluate the field condition and construct its carrier.
    pub(in crate::serde) setup: TokenStream,
    /// Local identifier bound by [`setup`](Self::setup).
    pub(in crate::serde) carrier: Ident,
    /// Expression indicating whether the field contributes to its container.
    pub(in crate::serde) included: TokenStream,
    /// Effective Serde field name, when this representation uses named fields.
    pub(in crate::serde) serialized_name: Option<String>,
    /// Condition under which Serde should be notified of a skipped field.
    pub(in crate::serde) skip_event: Option<TokenStream>,
}

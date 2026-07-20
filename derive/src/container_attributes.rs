// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict parsing boundary for container-level `redact` attributes.

use syn::DeriveInput;

/// Parsed container attributes supported by the current derive stage.
///
/// The type is intentionally empty until container-level serde support is
/// introduced. Its parser still rejects unsupported attributes eagerly so a
/// misspelled or premature option cannot be ignored silently.
pub(crate) struct ContainerAttributes;

impl ContainerAttributes {
    /// Parses and validates container-level attributes on `input`.
    ///
    /// # Parameters
    ///
    /// * `input` - Complete derive input whose container attributes are read.
    ///
    /// # Returns
    ///
    /// An empty validated attribute set when no container option is present.
    ///
    /// # Errors
    ///
    /// Returns a targeted error for every container-level `redact` attribute,
    /// because this derive stage supports field attributes only.
    pub(crate) fn parse(input: &DeriveInput) -> syn::Result<Self> {
        for attribute in &input.attrs {
            if attribute.path().is_ident("redact") {
                return Err(syn::Error::new_spanned(
                    attribute,
                    format!(
                        "Redact derive for `{}` does not support container attributes yet; \
                         put `level = \"...\"`, `skip`, `nested`, or `map` on a field",
                        input.ident,
                    ),
                ));
            }
        }
        Ok(Self)
    }
}

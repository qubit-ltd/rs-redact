// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Feature-aware expansion boundary for generated JSON field redaction.

/// Expands required json support when the runtime feature is enabled.
#[cfg(feature = "json")]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_json {
    ($($tokens:tt)*) => { $($tokens)* };
}

/// Reports an explicit compile error for required json support in a minimal
/// runtime.
#[cfg(not(feature = "json"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_json {
    ($($tokens:tt)*) => {
        compile_error!("#[redact(json)] requires the `json` feature of qubit-redact");
    };
}

// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Feature-aware expansion boundary for generated JSON field redaction.

#[cfg(feature = "json")]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_json {
    ($($tokens:tt)*) => { $($tokens)* };
}

#[cfg(not(feature = "json"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_json {
    ($($tokens:tt)*) => {
        compile_error!(
            "#[redact(json)] requires the `json` feature of qubit-redact"
        );
    };
}

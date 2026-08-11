// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Feature-aware expansion boundary for generated serde implementations.

#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_serde {
    ($($tokens:tt)*) => { $($tokens)* };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_serde {
    ($($tokens:tt)*) => {
        compile_error!("#[redact(serde)] requires the `serde` feature of qubit-redact");
    };
}

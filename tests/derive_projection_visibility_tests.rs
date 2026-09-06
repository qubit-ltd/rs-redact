// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(all(feature = "derive", feature = "serde"))]

use qubit_redact::domain::internal::RedactSerializeSource;

fn accepts_projection<T: RedactSerializeSource>() {
    let _ = std::any::type_name::<T>();
}

mod api {
    use qubit_redact_derive::Redact;

    #[derive(Redact)]
    #[redact(serde)]
    pub struct PublicRecord {
        pub name: String,
    }

    #[derive(Redact)]
    #[redact(serde)]
    pub enum PublicChoice {
        Empty,
        Text(String),
    }

    #[derive(Redact)]
    #[redact(serde)]
    pub struct PublicGeneric<T> {
        pub value: T,
    }

    #[derive(Redact)]
    #[redact(serde)]
    pub(crate) struct CrateRecord {
        value: String,
    }

    #[derive(Redact)]
    #[redact(serde)]
    struct PrivateRecord {
        value: String,
    }

    pub(super) fn assert_non_public_projections_compile() {
        super::accepts_projection::<CrateRecord>();
        super::accepts_projection::<PrivateRecord>();
    }
}

#[test]
fn test_projection_visibility_matches_derived_type_visibility() {
    let _ = api::PublicChoice::Empty;
    let _ = api::PublicChoice::Text(String::new());
    accepts_projection::<api::PublicRecord>();
    accepts_projection::<api::PublicChoice>();
    accepts_projection::<api::PublicGeneric<String>>();
    api::assert_non_public_projections_compile();
}

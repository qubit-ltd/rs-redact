// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Container implementations for explicit nested redaction.

use crate::domain::Redact;

impl<T: Redact> Redact for Option<T> {
    fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_>) {
        match self {
            None => writer.literal("None"),
            Some(value) => writer.tuple("Some", |fields| {
                fields.nested("", value);
            }),
        }
    }
}

impl<T: Redact + ?Sized> Redact for Box<T> {
    fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_>) {
        self.as_ref().write_redacted(writer)
    }
}

impl<T: Redact> Redact for Vec<T> {
    fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_>) {
        writer.sequence(|items| {
            items.for_each(self, |items, value| {
                items.nested_item(value);
            });
        });
    }
}

impl<T: Redact, const N: usize> Redact for [T; N] {
    fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_>) {
        writer.sequence(|items| {
            items.for_each(self, |items, value| {
                items.nested_item(value);
            });
        });
    }
}

macro_rules! tuple_redact {
    ($($name:ident),+ $(,)?) => {
        impl<$($name: Redact),+> Redact for ($($name,)+) {
            #[allow(non_snake_case)]
            fn write_redacted(&self, writer: &mut crate::domain::RedactionWriter<'_>) {
                let ($($name,)+) = self;
                writer.tuple("Tuple", |fields| {
                    $(fields.nested("", $name);)+
                });
            }
        }
    };
}

tuple_redact!(A);
tuple_redact!(A, B);
tuple_redact!(A, B, C);
tuple_redact!(A, B, C, D);
tuple_redact!(A, B, C, D, E);
tuple_redact!(A, B, C, D, E, F);
tuple_redact!(A, B, C, D, E, F, G);
tuple_redact!(A, B, C, D, E, F, G, H);
tuple_redact!(A, B, C, D, E, F, G, H, I);
tuple_redact!(A, B, C, D, E, F, G, H, I, J);
tuple_redact!(A, B, C, D, E, F, G, H, I, J, K);
tuple_redact!(A, B, C, D, E, F, G, H, I, J, K, L);

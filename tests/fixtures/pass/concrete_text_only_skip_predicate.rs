// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug)]
struct TextOnly;

#[derive(Debug, Redact)]
struct Concrete {
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<TextOnly>,
}

#[derive(Debug, Redact)]
struct ConcreteTuple(#[serde(skip_serializing_if = "Option::is_none")] Option<TextOnly>);

#[derive(Debug, Redact)]
enum External {
    Named {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<TextOnly>,
    },
    Tuple(#[serde(skip_serializing_if = "Option::is_none")] Option<TextOnly>),
}

#[derive(Debug, Redact)]
#[serde(tag = "kind")]
enum Internal {
    Named {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<TextOnly>,
    },
}

#[derive(Debug, Redact)]
#[serde(tag = "kind", content = "payload")]
enum Adjacent {
    Named {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<TextOnly>,
    },
    Tuple(#[serde(skip_serializing_if = "Option::is_none")] Option<TextOnly>),
}

#[derive(Debug, Redact)]
#[serde(untagged)]
enum Untagged {
    Named {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<TextOnly>,
    },
    Tuple(#[serde(skip_serializing_if = "Option::is_none")] Option<TextOnly>),
}

fn main() {
    let value = Concrete { value: Some(TextOnly) };
    let redactor = Redactor::standard();
    assert!(format!("{}", redactor.redact_view(&value)).contains("TextOnly"));
    assert!(redactor.redact_text(&value).complete_text().is_ok());
    let tuple = ConcreteTuple(Some(TextOnly));
    let external_named = External::Named { value: Some(TextOnly) };
    let external_tuple = External::Tuple(Some(TextOnly));
    let internal = Internal::Named { value: Some(TextOnly) };
    let adjacent_named = Adjacent::Named { value: Some(TextOnly) };
    let adjacent_tuple = Adjacent::Tuple(Some(TextOnly));
    let untagged_named = Untagged::Named { value: Some(TextOnly) };
    let untagged_tuple = Untagged::Tuple(Some(TextOnly));
    for text in [
        redactor.redact_text(&tuple),
        redactor.redact_text(&external_named),
        redactor.redact_text(&external_tuple),
        redactor.redact_text(&internal),
        redactor.redact_text(&adjacent_named),
        redactor.redact_text(&adjacent_tuple),
        redactor.redact_text(&untagged_named),
        redactor.redact_text(&untagged_tuple),
    ] {
        assert!(text.complete_text().is_ok());
    }
}

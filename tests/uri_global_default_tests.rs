// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
// =============================================================================
//! Isolated global-configuration tests for URI redaction policy construction.

#![cfg(feature = "uri")]

use qubit_redact::{
    GlobalRedactionConfig, RedactionPolicy,
    uri::{UriFragmentPolicy, UriPathPolicy, UriRedactionPolicy, UriRedactor},
};

/// Verifies URI defaults preserve the complete installed policy snapshot.
#[test]
fn test_uri_policy_defaults_preserve_global_snapshot() {
    let expected = UriRedactionPolicy::builder_from(&RedactionPolicy::standard())
        .path_policy(UriPathPolicy::Redact)
        .fragment_policy(UriFragmentPolicy::Preserve)
        .build()
        .expect("the custom URI policy should be valid");
    GlobalRedactionConfig::standard()
        .with_uri_policy(expected.clone())
        .install()
        .expect("this isolated test process installs the global configuration once");

    assert_eq!(UriRedactionPolicy::default(), expected);
    assert_eq!(UriRedactor::default().policy(), &expected);
}

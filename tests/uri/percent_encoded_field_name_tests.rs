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
//! Tests for strict percent decoding of URI field names.

use qubit_redact::uri::decode_percent_encoded_field_name;

/// Verifies valid percent-encoded UTF-8 is decoded without form semantics.
#[test]
fn test_decode_percent_encoded_field_name_decodes_utf8() {
    assert_eq!(
        decode_percent_encoded_field_name("display%E4%B8%AD%E6%96%87")
            .as_deref(),
        Some("display中文"),
    );
    assert_eq!(
        decode_percent_encoded_field_name("literal%2Bplus").as_deref(),
        Some("literal+plus"),
    );
}

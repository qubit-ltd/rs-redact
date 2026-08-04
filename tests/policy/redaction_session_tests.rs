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
//! Tests for operation-scoped redaction budgets.

use qubit_redact::{
    InputOutputLimit,
    RedactionPolicy,
    RedactionSession,
};

/// Verifies a diagnostic session shares input and output consumption with a
/// child scope.
#[test]
fn test_diagnostic_session_shares_budget_with_scope() {
    let limit = InputOutputLimit::new(8, 64)
        .expect("the test input/output limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let session = RedactionSession::diagnostic(&policy);

    assert!(session.consume_input(3));
    assert!(session.consume_output(4));
    {
        let child_limit = InputOutputLimit::new(2, 37)
            .expect("the child limit should be valid");
        let mut child = session.scope(child_limit);
        assert!(child.consume_input(2));
        assert!(child.consume_output(37));
    }

    assert_eq!(session.remaining_input_bytes(), 3);
    assert_eq!(session.remaining_output_bytes(), 23);
}

/// Verifies input exhaustion still leaves room for a fail-closed marker.
#[test]
fn test_diagnostic_session_rejects_consumption_after_exhaustion() {
    let limit = InputOutputLimit::new(3, 64)
        .expect("the test input/output limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let session = RedactionSession::diagnostic(&policy);

    assert!(!session.consume_input(4));
    assert!(session.is_exhausted());
    assert!(session.consume_output(1));
}

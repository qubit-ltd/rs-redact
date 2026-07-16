# rs-sanitize Final Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Complete the nine confirmed hardening changes in \`rs-sanitize\` and \`rs-http\` without adding generic secret scanning or changing unrelated downstream crates.

**Architecture:** Strengthen canonical field matching and presets in \`rs-sanitize\` core, make opaque-text exposure explicit in HTTP body results, and keep multipart parsing state in named private types. In \`rs-http\`, make text-body and URL-path handling explicit policy inputs to the existing log sanitizer while preserving URL path compatibility by default.

**Tech Stack:** Rust 2024, Cargo integration tests, \`url\`, existing \`qubit-sanitize\` adapters, repository CI shell scripts.

**Confirmed design:** \`docs/superpowers/specs/2026-07-16-rs-sanitize-final-hardening-design.md\`

## Execution constraints

- Use strict TDD for every behavior change: write one focused failing test, run it and confirm the intended failure, then make the smallest implementation change.
- Keep tests in the mirrored external \`tests/\` tree; do not add inline \`#[cfg(test)]\` modules.
- Keep one significant Rust type per file and mirror new source files with dedicated external test files when the type is public.
- Do not add a generic scanner, regex secret dictionary, entropy detector, vendor webhook parser, or arbitrary text analyzer.
- Preserve existing \`rs-mime\` and \`rs-magika\` working-tree changes; those repositories are validation-only and should not be edited.
- Do not run \`git add\`, \`git commit\`, or \`git push\`. Each task ends with a diff checkpoint instead of a commit.
- Before implementation, apply the \`using-git-worktrees\` skill and choose coordinated isolation for both \`rs-sanitize\` and \`rs-http\`, or obtain explicit consent to work in the current checkouts.
- Before claiming completion, run the \`verification-before-completion\` skill and report fresh command output.

## Task 1: Strengthen core field matching and defaults

**Files:**

- Modify: \`rs-sanitize/src/core/field_name.rs\`
- Modify: \`rs-sanitize/src/core/sensitive_fields.rs\`
- Modify: \`rs-sanitize/src/core/sensitive_field_preset.rs\`
- Modify: \`rs-sanitize/src/core/default_sensitive_fields.rs\`
- Test: \`rs-sanitize/tests/core/sensitive_fields_tests.rs\`
- Test: \`rs-sanitize/tests/core/field_sanitizer_tests.rs\`
- Test: \`rs-sanitize/tests/core/sensitive_field_preset_tests.rs\`
- Test: \`rs-sanitize/tests/lib_tests.rs\`

- [ ] Add failing bracket-boundary tests to \`sensitive_fields_tests.rs\`.

~~~rust
#[test]
fn test_sensitive_fields_exact_or_suffix_matches_bracketed_paths() {
    let fields = SensitiveFields::default();

    assert_eq!(
        fields.sensitivity_level("user[password]", NameMatchMode::ExactOrSuffix),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        fields.sensitivity_level(
            "credentials[api_key]",
            NameMatchMode::ExactOrSuffix,
        ),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        fields.sensitivity_level("notpassword", NameMatchMode::ExactOrSuffix),
        None,
    );
}
~~~

- [ ] Run the focused RED test and confirm bracketed names do not yet match.

~~~bash
cd rs-sanitize
cargo test --test core_tests sensitive_fields_exact_or_suffix_matches_bracketed_paths
~~~

- [ ] Add \`'[' | ']'\` to the separator predicate used by canonicalization in \`field_name.rs\`; keep the suffix-boundary check unchanged so \`notpassword\` remains a non-match.

~~~rust
pub fn canonicalize_field_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|ch| !is_field_separator(*ch))
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_field_separator(ch: char) -> bool {
    matches!(ch, '_' | '-' | '.' | '[' | ']') || ch.is_whitespace()
}
~~~

- [ ] Re-run the focused test and confirm GREEN.

- [ ] Add a failing strongest-wins regression to \`sensitive_fields_tests.rs\`.

~~~rust
#[test]
fn test_sensitive_fields_extend_preset_does_not_downgrade_existing_level() {
    let mut fields = SensitiveFields::new();
    fields.insert("authorization", SensitivityLevel::Secret);

    fields.extend_preset(SensitiveFieldPreset::Http);

    assert_eq!(
        fields.sensitivity_level("authorization", NameMatchMode::Exact),
        Some(SensitivityLevel::Secret),
    );
}
~~~

- [ ] Run RED, then change \`SensitiveFields::extend_preset\` to call \`insert_strongest\` for every preset entry.

~~~bash
cargo test --test core_tests sensitive_fields_extend_preset_does_not_downgrade_existing_level
~~~

~~~rust
for &(field, level) in preset.fields() {
    self.insert_strongest(field, level);
}
~~~

- [ ] Add a facade-level regression in \`field_sanitizer_tests.rs\` proving \`FieldSanitizer::extend_preset\` inherits strongest-wins behavior, then run RED/GREEN with:

~~~bash
cargo test --test core_tests field_sanitizer_extend_preset_does_not_downgrade_existing_level
~~~

- [ ] Add failing Credentials preset assertions for the four confirmed fields in \`sensitive_field_preset_tests.rs\`.

~~~rust
assert_eq!(
    fields.sensitivity_level("secret_key", NameMatchMode::Exact),
    Some(SensitivityLevel::Secret),
);
assert_eq!(
    fields.sensitivity_level("secret_access_key", NameMatchMode::Exact),
    Some(SensitivityLevel::Secret),
);
assert_eq!(
    fields.sensitivity_level("access_key", NameMatchMode::Exact),
    Some(SensitivityLevel::High),
);
assert_eq!(
    fields.sensitivity_level("access_key_id", NameMatchMode::Exact),
    Some(SensitivityLevel::Medium),
);
~~~

- [ ] Run the preset test RED, add those entries to \`SensitiveFieldPreset::Credentials\`, then run it GREEN.

~~~bash
cargo test --test core_tests sensitive_field_preset_credentials_fields
~~~

- [ ] Add a failing output-level test in \`field_sanitizer_tests.rs\` covering uppercase environment-style names and expected mask strength:

~~~rust
assert_eq!(
    sanitizer.sanitize_value(
        "SECRET_KEY",
        "abcdef",
        NameMatchMode::ExactOrSuffix,
    ),
    "<redacted>",
);
assert_eq!(
    sanitizer.sanitize_value(
        "AWS_SECRET_ACCESS_KEY",
        "abcdef",
        NameMatchMode::ExactOrSuffix,
    ),
    "<redacted>",
);
assert_eq!(
    sanitizer.sanitize_value(
        "AWS_ACCESS_KEY_ID",
        "AKIA12345678",
        NameMatchMode::ExactOrSuffix,
    ),
    "****8",
);
~~~

Also assert \`AWS_ACCESS_KEY\` resolves to High and renders \`****\`.

- [ ] Run the focused test RED/GREEN.

- [ ] Add a compile-time API assertion to \`tests/lib_tests.rs\`:

~~~rust
let fields: &'static [(&'static str, SensitivityLevel)] =
    DEFAULT_EXTRA_FIELDS;
assert!(!fields.is_empty());
~~~

- [ ] Run RED, change the constant to a slice, and update all iteration sites to destructure references.

~~~bash
cargo test --test lib_tests test_lib_exports_public_api
~~~

~~~rust
pub const DEFAULT_EXTRA_FIELDS: &[(&str, SensitivityLevel)] = &[
    ("auth_app_token", SensitivityLevel::High),
    ("auth_user_token", SensitivityLevel::High),
    ("license_key", SensitivityLevel::Medium),
];
~~~

~~~rust
for &(field, level) in DEFAULT_EXTRA_FIELDS {
    fields.insert_strongest(field, level);
}
~~~

- [ ] Run the affected core suites and inspect the diff.

~~~bash
cargo test --test core_tests
cargo test --test lib_tests
git diff -- src/core tests/core tests/lib_tests.rs
~~~

## Task 2: Make multipart precedence and opaque-text exposure explicit

**Files:**

- Create: \`rs-sanitize/src/adapter/http/internal/multipart_part_metadata.rs\`
- Create: \`rs-sanitize/src/adapter/http/internal/multipart_sanitization.rs\`
- Modify: \`rs-sanitize/src/adapter/http/internal/mod.rs\`
- Modify: \`rs-sanitize/src/adapter/http/multipart.rs\`
- Modify: \`rs-sanitize/src/adapter/http/body_sanitization_status.rs\`
- Modify: \`rs-sanitize/src/adapter/http/http_body_sanitizer.rs\`
- Test: \`rs-sanitize/tests/adapter/http/http_body_sanitizer_tests.rs\`
- Test: \`rs-sanitize/tests/adapter/http/body_sanitization_tests.rs\`

- [ ] Add a failing multipart regression showing a filename always wins over a low-sensitivity field name.

~~~rust
#[test]
fn test_http_body_sanitizer_redacts_file_part_before_field_policy() {
    let mut sanitizer = HttpBodySanitizer::default();
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("attachment", SensitivityLevel::Low);
    let body = b"--b\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nraw-file-secret\r\n--b--\r\n";

    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert!(result.content().contains("<redacted: file part>"));
    assert!(!result.content().contains("raw-file-secret"));
}
~~~

- [ ] Run RED and confirm the current field sensitivity branch executes before filename redaction.

~~~bash
cd rs-sanitize
cargo test --test adapter_tests http_body_sanitizer_redacts_file_part_before_field_policy
~~~

- [ ] Introduce private \`MultipartPartMetadata<'a>\` to parse and expose \`name\`, \`filename\`, and \`content_type\`, then move filename detection ahead of sensitivity lookup.

~~~rust
pub(super) struct MultipartPartMetadata<'a> {
    name: Option<String>,
    filename: Option<String>,
    content_type: Option<&'a str>,
}
~~~

The parser must treat both \`filename\` and RFC-compatible \`filename*\` as file evidence. Do not change the existing malformed-input fallback or markers.

- [ ] Re-run the file test GREEN, then add a separate \`filename*\` regression and run it GREEN.

- [ ] Add a failing control-character test using a multipart field name containing ESC and assert the summary contains an escaped representation and no raw ESC byte.

~~~rust
assert!(result.content().contains(r#"note\u{1b}[31m="#));
assert!(!result.content().contains('\u{1b}'));
~~~

- [ ] Run RED, render only the displayed field name through \`escape_debug\`-equivalent escaping, and leave the original field name available for sensitivity matching.

~~~bash
cargo test --test adapter_tests http_body_sanitizer_escapes_multipart_field_name_controls
~~~

- [ ] Add failing status tests for top-level \`text/plain\` and a multipart text part under \`TextBodyPolicy::PassThrough\`.

~~~rust
assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
~~~

- [ ] Run both RED tests.

~~~bash
cargo test --test adapter_tests passed_through -- --nocapture
~~~

- [ ] Add \`PassedThrough\` to the existing non-exhaustive \`BodySanitizationStatus\`.

~~~rust
/// The output contains opaque text that policy explicitly allowed unchanged.
PassedThrough,
~~~

- [ ] Add private \`MultipartSanitization\` as a named internal result.

~~~rust
pub(super) struct MultipartSanitization {
    content: String,
    contains_passed_through_text: bool,
}

impl MultipartSanitization {
    #[inline]
    pub(super) fn new(
        content: String,
        contains_passed_through_text: bool,
    ) -> Self {
        Self {
            content,
            contains_passed_through_text,
        }
    }

    #[inline(always)]
    pub(super) fn content(&self) -> &str {
        &self.content
    }

    #[inline(always)]
    pub(super) fn into_content(self) -> String {
        self.content
    }

    #[inline(always)]
    pub(super) const fn contains_passed_through_text(&self) -> bool {
        self.contains_passed_through_text
    }
}
~~~

- [ ] Return \`MultipartSanitization\` from each successfully parsed part and from \`sanitize_multipart\`; aggregate \`contains_passed_through_text\` with boolean OR while collecting lines. Map top-level opaque pass-through and multipart exposure to \`BodySanitizationStatus::PassedThrough\`; retain \`Sanitized\` for structured or redacted output.

- [ ] Run all focused tests GREEN, then run the full adapter target and inspect the diff.

~~~bash
cargo test --test adapter_tests
git diff -- src/adapter/http tests/adapter/http
~~~

## Task 3: Split HTTP body dispatch without changing behavior

**Files:**

- Modify: \`rs-sanitize/src/adapter/http/http_body_sanitizer.rs\`
- Test: \`rs-sanitize/tests/adapter/http/http_body_sanitizer_tests.rs\`

- [ ] Before refactoring, run the existing characterization tests for multipart priority, preview source length/truncation, NDJSON, JSON sniffing, and form dispatch. Add a source-length assertion only if no existing test covers it.

~~~bash
cd rs-sanitize
cargo test --test adapter_tests http_body_sanitizer -- --nocapture
~~~

- [ ] Extract private handlers with explicit responsibilities; keep \`sanitize_body_inner\` as the ordered dispatcher.

~~~rust
fn sanitize_multipart_body(
    &self,
    bytes: &[u8],
    source_len: usize,
    content_type: &str,
    input_kind: BodyInputKind,
    match_mode: NameMatchMode,
) -> BodySanitization;

fn sanitize_ndjson_body(
    &self,
    bytes: &[u8],
    source_len: usize,
    input_kind: BodyInputKind,
    match_mode: NameMatchMode,
) -> BodySanitization;

fn sanitize_json_body(
    &self,
    bytes: &[u8],
    source_len: usize,
    input_kind: BodyInputKind,
    match_mode: NameMatchMode,
) -> BodySanitization;

fn sanitize_form_body(
    &self,
    bytes: &[u8],
    source_len: usize,
    match_mode: NameMatchMode,
) -> BodySanitization;

fn sanitize_fallback_body(
    &self,
    bytes: &[u8],
    source_len: usize,
    content_type: Option<&str>,
) -> BodySanitization;
~~~

Use the concrete existing argument types rather than a context tuple. Preserve the current order: declared multipart, declared NDJSON, declared JSON, declared form, then fallback/sniffing.

- [ ] Keep source-length calculation and marker selection at their existing semantic layer. Do not add \`#[inline]\` to the dispatcher or complex handlers.

- [ ] Run the characterization tests after each extraction and confirm identical expected strings/statuses.

- [ ] Run the full adapter target and inspect only this refactor's diff.

~~~bash
cargo test --test adapter_tests
git diff -- src/adapter/http/http_body_sanitizer.rs tests/adapter/http/http_body_sanitizer_tests.rs
~~~

## Task 4: Make rs-http opaque text redaction the default

**Files:**

- Modify: \`rs-http/src/sanitize/log_sanitize_policy.rs\`
- Modify: \`rs-http/src/sanitize/log_sanitizer.rs\`
- Modify: \`rs-http/src/sanitize/mod.rs\`
- Modify: \`rs-http/src/lib.rs\`
- Test: \`rs-http/tests/sanitize/log_sanitize_policy_tests.rs\`
- Test: \`rs-http/tests/sanitize/log_sanitizer_tests.rs\`
- Test: \`rs-http/tests/client/http_logger_policy_tests.rs\`
- Test: \`rs-http/tests/error/http_error_tests.rs\`

- [ ] Add failing policy tests that default is \`TextBodyPolicy::Redact\`, and that getter, setter, and builder round-trip \`PassThrough\`.

~~~rust
assert_eq!(
    LogSanitizePolicy::default().text_body_policy(),
    TextBodyPolicy::Redact,
);

let mut policy = LogSanitizePolicy::default();
policy.set_text_body_policy(TextBodyPolicy::PassThrough);
assert_eq!(
    policy.text_body_policy(),
    TextBodyPolicy::PassThrough,
);
assert_eq!(
    LogSanitizePolicy::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough)
        .text_body_policy(),
    TextBodyPolicy::PassThrough,
);
~~~

- [ ] Run RED.

~~~bash
cd rs-http
cargo test --test mod log_sanitize_policy_text_body_policy
~~~

- [ ] Add the policy field and ordered methods. Re-export \`TextBodyPolicy\` from the crate root.

~~~rust
pub struct LogSanitizePolicy {
    sensitive_headers: SensitiveFields,
    sensitive_query_params: SensitiveFields,
    sensitive_body_fields: SensitiveFields,
    text_body_policy: TextBodyPolicy,
}
~~~

Initialize this field to \`TextBodyPolicy::Redact\` in both \`empty()\` and
\`Default::default()\`; “empty” removes sensitive-name sets but does not weaken
opaque-text safety.

~~~rust
#[inline(always)]
pub const fn text_body_policy(&self) -> TextBodyPolicy;

#[inline(always)]
pub fn set_text_body_policy(&mut self, policy: TextBodyPolicy);

#[must_use]
#[inline]
pub fn with_text_body_policy(mut self, policy: TextBodyPolicy) -> Self;
~~~

- [ ] Change \`LogSanitizer::new\` to pass \`policy.text_body_policy()\` into \`HttpBodySanitizer\` instead of hard-coding \`PassThrough\`.

- [ ] Add failing behavior tests proving default TRACE request/response text, multipart opaque text, and non-success \`HttpError.message\` do not contain the secret; add explicit \`PassThrough\` tests proving opt-in restores the original text.

- [ ] Run focused RED tests, implement only policy propagation, and run GREEN.

~~~bash
cargo test --test mod text_body -- --nocapture
cargo test --test mod multipart -- --nocapture
cargo test --test mod http_error -- --nocapture
~~~

- [ ] Update \`LogSanitizer::for_debug\` to copy the caller's text-body policy after starting from built-in strongest field defaults. Add a regression that custom field levels still cannot downgrade built-ins while \`PassThrough\` is preserved.

- [ ] Run all sanitize, logger-policy, and error tests and inspect the diff.

~~~bash
cargo test --test mod sanitize
cargo test --test mod http_logger_policy
cargo test --test mod http_error
git diff -- src/sanitize src/lib.rs tests/sanitize tests/client/http_logger_policy_tests.rs tests/error/http_error_tests.rs
~~~

## Task 5: Add an explicit rs-http URL path policy

**Files:**

- Create: \`rs-http/src/sanitize/url_path_policy.rs\`
- Modify: \`rs-http/src/sanitize/mod.rs\`
- Modify: \`rs-http/src/sanitize/log_sanitize_policy.rs\`
- Modify: \`rs-http/src/sanitize/log_sanitizer.rs\`
- Modify: \`rs-http/src/lib.rs\`
- Create: \`rs-http/tests/sanitize/url_path_policy_tests.rs\`
- Modify: \`rs-http/tests/sanitize/mod.rs\`
- Modify: \`rs-http/tests/sanitize/log_sanitize_policy_tests.rs\`
- Modify: \`rs-http/tests/sanitize/log_sanitizer_tests.rs\`
- Modify: \`rs-http/README.md\`
- Modify: \`rs-http/README.zh_CN.md\`

- [ ] Add the mirrored external enum tests first.

~~~rust
#[test]
fn test_url_path_policy_defaults_to_preserve() {
    assert_eq!(UrlPathPolicy::default(), UrlPathPolicy::Preserve);
}

#[test]
fn test_url_path_policy_is_copy_and_equatable() {
    let policy = UrlPathPolicy::Redact;
    assert_eq!(policy, policy);
}
~~~

- [ ] Register the test module and run RED because the public type does not exist.

~~~bash
cd rs-http
cargo test --test mod url_path_policy -- --nocapture
~~~

- [ ] Add and re-export the public enum exactly as designed.

~~~rust
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UrlPathPolicy {
    #[default]
    Preserve,
    Redact,
}
~~~

- [ ] Add failing \`LogSanitizePolicy\` getter/setter/builder tests. Implement a \`url_path_policy\` field defaulting to Preserve; place \`with_url_path_policy\` with constructor/builders and place the getter/setter with the public accessors.

~~~rust
#[inline(always)]
pub const fn url_path_policy(&self) -> UrlPathPolicy;

#[inline(always)]
pub fn set_url_path_policy(&mut self, policy: UrlPathPolicy);

#[must_use]
#[inline]
pub fn with_url_path_policy(mut self, policy: UrlPathPolicy) -> Self;
~~~

- [ ] Add failing sanitizer tests for both policy modes. Preserve must retain \`/tenant/secret-id\`; Redact must omit it while still masking userinfo, fragment, and sensitive query values.

~~~rust
let url = Url::parse(
    "https://alice:password@example.com/tenant/secret-id?access_token=query-secret#fragment-secret",
)
.unwrap();

let sanitized = LogSanitizer::new(
    LogSanitizePolicy::default()
        .with_url_path_policy(UrlPathPolicy::Redact),
)
.sanitize_url(&url);

assert!(!sanitized.contains("tenant/secret-id"));
assert!(!sanitized.contains("query-secret"));
assert!(!sanitized.contains("alice"));
assert!(!sanitized.contains("fragment-secret"));
assert!(sanitized.contains("/%3Credacted%3E?"));
~~~

- [ ] Run RED, then clone the URL and replace only its path with \`/<redacted>\` before delegating to the existing core \`UrlSanitizer\`. Do not implement vendor-specific path parsing.

~~~rust
let mut sanitized_url = url.clone();
if self.url_path_policy == UrlPathPolicy::Redact {
    sanitized_url.set_path("/<redacted>");
}
self.url_sanitizer
    .sanitize_url(&sanitized_url, LOG_NAME_MATCH_MODE)
~~~

- [ ] Store \`url_path_policy\` in \`LogSanitizer\` and copy it in \`for_debug\`. Add a debug regression proving explicit Redact applies to request/response/error debug URLs.

- [ ] Replace absolute “log-safe” Rustdoc/README claims with accurate policy wording: userinfo, fragment, and recognized query fields are masked; path is preserved by default and callers must select \`UrlPathPolicy::Redact\` when path segments may contain secrets. Update English and Chinese documents together.

- [ ] Run the URL/policy/debug-focused tests and inspect the diff.

~~~bash
cargo test --test mod sanitize -- --nocapture
cargo test --test mod debug -- --nocapture
git diff -- src/sanitize src/lib.rs tests/sanitize README.md README.zh_CN.md
~~~

## Task 6: Complete method-order, inline, and Rustdoc audit

**Files:**

- Modify only touched Rust files in \`rs-sanitize/src/\`
- Modify only touched Rust files in \`rs-http/src/\`
- Test: existing external test targets

- [ ] For each touched inherent impl, order methods as constructors and builder-style \`with_*\`, then public getters/setters, then restricted/private helpers. Do not reorder \`FieldSanitizePolicy\` or \`MaskPolicies\`: their current builder-before-getter order is already correct.

- [ ] Apply \`#[inline(always)]\` to trivial getters, setters, and pure forwarding facades; use \`#[inline]\` for short non-forwarding builders; leave body dispatch, multipart parsing, and URL mutation logic without forced inline.

- [ ] Add complete Rustdoc to new public variants, policy fields exposed via methods, and public methods, including policy defaults and security boundary. Keep private type comments concise and explain invariants rather than syntax.

- [ ] Run formatting and targeted tests; inspect formatting changes before proceeding.

~~~bash
cd rs-sanitize
cargo fmt --all -- --check
cargo test --test core_tests
cargo test --test adapter_tests
cargo test --test lib_tests

cd ../rs-http
cargo fmt --all -- --check
cargo test --test mod sanitize
~~~

## Task 7: Run repository and downstream verification

**Files:**

- Verify: all modified files in \`rs-sanitize\`
- Verify: all modified files in \`rs-http\`
- Verify only: \`rs-command\`
- Inspect only: \`rs-mime\`, \`rs-magika\`

- [ ] In \`rs-sanitize\`, run the repository-required validation order exactly.

~~~bash
cd rs-sanitize
./align-ci.sh
./ci-check.sh
~~~

- [ ] Only if \`ci-check.sh\` reports coverage below its threshold, run exactly:

~~~bash
./coverage.sh json
~~~

- [ ] Review \`rs-sanitize\` status and diff; confirm no unrelated files changed and the spec/plan remain untracked documentation unless the user later authorizes git operations.

~~~bash
git status --short
git diff --check
git diff
~~~

- [ ] In \`rs-http\`, run the same required validation order.

~~~bash
cd ../rs-http
./align-ci.sh
./ci-check.sh
~~~

- [ ] Only if its CI reports insufficient coverage, run exactly:

~~~bash
./coverage.sh json
~~~

- [ ] Review \`rs-http\` status, diff, public re-exports, and README parity.

~~~bash
git status --short
git diff --check
git diff
~~~

- [ ] Validate the direct downstream \`rs-command\` against the updated local dependency without editing it.

~~~bash
cd ../rs-command
./align-ci.sh
./ci-check.sh
~~~

Run \`./coverage.sh json\` only if this CI reports coverage below threshold.

- [ ] Inspect, but do not alter, the indirect downstream working trees.

~~~bash
cd ../rs-mime
git status --short
cd ../rs-magika
git status --short
~~~

- [ ] Confirm the final contract explicitly:

  - \`PassedThrough\` is returned for all opaque plaintext exposure, including multipart aggregation.
  - file evidence overrides multipart field sensitivity.
  - preset extension cannot lower an existing level.
  - four credential names and bracketed field paths behave as designed.
  - \`DEFAULT_EXTRA_FIELDS\` is a slice.
  - \`rs-http\` opaque text defaults to Redact and PassThrough is explicit.
  - URL path defaults to Preserve and explicit Redact hides the original path.
  - documentation no longer promises unconditional log safety.
  - \`rs-mime\` and \`rs-magika\` user changes are untouched.

- [ ] Capture fresh verification output in the final handoff. Do not claim passing status from earlier runs and do not perform git commits unless the user separately authorizes them.

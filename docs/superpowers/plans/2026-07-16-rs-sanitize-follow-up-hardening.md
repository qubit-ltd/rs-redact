# rs-sanitize Follow-up Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two confirmed sanitization gaps, add semantic `must_use` contracts across `src`, and reduce cloning and suffix-matching overhead without changing public API paths.

**Architecture:** Keep the existing adapters and matching model. Fix argv parsing by recognizing a new bare sensitive option before consuming a pending value, add `password_confirmation` to the credential preset, store `SensitiveFields` in `Arc<BTreeMap<...>>` with `Arc::make_mut`, and resolve `ExactOrSuffix` by looking up canonical suffixes from longest to shortest. Apply `must_use` at the type level when every producer has the same obligation and at the operation level for sanitized outputs and pure decisions whose result must be consumed.

**Tech Stack:** Rust 2024, standard-library `Arc` and `BTreeMap`, existing integration-test layout, Cargo doctests.

## Global Constraints

- Preserve every public type path and method signature.
- Keep all tests under `tests/`; use compile-fail doctests only for externally observable warning contracts.
- Do not add dependencies or expose test-only APIs.
- Do not change `session` or `session_id` sensitivity in this change.
- Do not run `git add`, `git commit`, or `git push` without explicit user authorization.

---

### Task 1: Consecutive sensitive argv options

**Files:**
- Modify: `tests/adapter/argv_sanitizer_tests.rs`
- Modify: `src/adapter/argv_sanitizer.rs`

**Interfaces:**
- Consumes: `ArgvSanitizer::sanitize_argv` and `NameMatchMode::ExactOrSuffix`.
- Produces: unchanged public API with fail-closed handling of a recognized sensitive option following another sensitive option that has no value.

- [ ] Add `test_argv_sanitizer_recognizes_consecutive_sensitive_options` with input `['cmd', '--password', '--token', 'second-secret']` and expected output `['cmd', '--password', '--token', '****']`.
- [ ] Run `cargo test --all-features --test adapter_tests test_argv_sanitizer_recognizes_consecutive_sensitive_options -- --exact` and verify the old state machine exposes `second-secret`.
- [ ] Add a private `sensitive_option_name` helper and make the pending-value branch transfer pending state when the current token is another recognized bare sensitive option.
- [ ] Rerun the focused test and the full argv sanitizer test module.

### Task 2: Password-confirmation default

**Files:**
- Modify: `tests/core/field_sanitizer_tests.rs`
- Modify: `tests/core/sensitive_field_preset_tests.rs`
- Modify: `src/core/sensitive_field_preset.rs`

**Interfaces:**
- Consumes: `SensitiveFieldPreset::Credentials` and `FieldSanitizer::sensitivity_for_name`.
- Produces: `password_confirmation`, `passwordConfirmation`, and contextual suffixes such as `new_password_confirmation` resolve to `SensitivityLevel::Secret` in `ExactOrSuffix` mode.

- [ ] Add `test_field_sanitizer_masks_password_confirmation_suffixes` covering snake case, camel case, and a contextual prefix.
- [ ] Run the focused test and verify all cases currently return unmasked values or `None`.
- [ ] Add `('password_confirmation', SensitivityLevel::Secret)` to `CREDENTIALS_FIELDS`, increase its array size and preset-length assertion from 10 to 11.
- [ ] Rerun the focused and preset tests.

### Task 3: Semantic must-use audit

**Files:**
- Modify: every applicable Rust source under `src/core`, `src/adapter`, and `src/adapter/http` identified by the source-wide audit.
- Test: doctests attached to representative public contracts in `src/core/field_sanitizer.rs`, `src/adapter/argv_sanitizer.rs`, `src/core/redacted_debug.rs`, and `src/adapter/http/body_sanitization.rs`.

**Interfaces:**
- Consumes: all existing source return values.
- Produces: compiler warnings when a sanitizer result, redaction wrapper, structured body result, builder/configuration value, or meaningful pure query is discarded; no redundant annotation on `Option`, `Result`, iterators, or methods returning a type already protected at type level.

- [ ] Add compile-fail doctests using `#![deny(unused_must_use)]` for discarded `sanitize_value`, `sanitize_argv`, `redacted_debug`, and `sanitize_body` results.
- [ ] Run `cargo test --all-features --doc` and verify the doctests fail because the discarded values still compile.
- [ ] Add type-level `#[must_use]` to sanitizer/configuration result types whose every producer has the same obligation, including `RedactedDebug`, `BodySanitization`, and internal `MultipartSanitization`.
- [ ] Add operation-level `#[must_use]` to sanitized `String`/`Vec`/`Cow`/map/tuple outputs and pure scalar/reference decisions that are not already protected by their return type.
- [ ] Re-scan every function and method in `src`; explicitly leave unit-returning mutators and `Option`/`Result`/iterator producers unannotated unless they carry a separate obligation.
- [ ] Run doctests, no-default-feature tests, and all-feature tests to catch redundant or missing contracts.

### Task 4: Arc copy-on-write SensitiveFields

**Files:**
- Modify: `tests/core/sensitive_fields_tests.rs`
- Modify: `src/core/sensitive_fields.rs`

**Interfaces:**
- Consumes: existing `SensitiveFields: Clone + Eq` API and all mutators.
- Produces: cheap clones sharing `Arc<BTreeMap<String, SensitivityLevel>>`; the first mutation detaches via `Arc::make_mut`; `clear` installs a fresh empty map without cloning shared entries.

- [ ] Add characterization test `test_sensitive_fields_clone_mutation_is_independent` covering insert, remove, and clear after cloning.
- [ ] Run the characterization test before the refactor.
- [ ] Replace the field with `Arc<BTreeMap<...>>`, construct it with `Arc::new`, route insert/remove/entry mutations through `Arc::make_mut`, and reset `clear` with a fresh empty `Arc`.
- [ ] Rerun all `SensitiveFields` and policy clone tests.

### Task 5: Longest-suffix direct lookup

**Files:**
- Modify: `src/core/sensitive_fields.rs`
- Modify: `src/core/field_sanitizer.rs`
- Verify: `tests/core/field_sanitizer_tests.rs`

**Interfaces:**
- Consumes: canonical suffixes ordered shortest to longest.
- Produces: exact behavior preserved; `ExactOrSuffix` iterates suffixes in reverse and calls a restricted canonical-key lookup instead of scanning every configured field.

- [ ] Add `SensitiveFields::level_for_canonical` with `pub(super)` visibility and direct `BTreeMap::get` semantics; keep `level_for` as the public canonicalizing entry point.
- [ ] Replace the field scan in `sensitivity_for_name` with `canonicalize_field_name_suffixes(name).into_iter().rev().find_map(...)`.
- [ ] Run focused exact, boundary, longest-suffix, and unbounded-suffix tests.

### Task 6: Repository verification and downstream compatibility

**Files:**
- Verify: `rs-sanitize` source, tests, docs, and scripts.
- Inspect: `rs-command` and `rs-http` compile-facing use sites without modifying them unless compilation proves an in-scope compatibility issue.

**Interfaces:**
- Produces: formatted source, CI-equivalent checks, and preserved downstream public calls.

- [ ] Run `./align-ci.sh` from `rs-sanitize` and inspect all resulting changes.
- [ ] Run `./ci-check.sh` from `rs-sanitize`.
- [ ] Run `./coverage.sh json` only if CI reports coverage below its threshold.
- [ ] Run focused downstream checks only if the source audit or CI reveals a public compatibility concern.
- [ ] Review `git --no-pager diff`, re-run the semantic `must_use` inventory, and confirm no unrelated files changed.

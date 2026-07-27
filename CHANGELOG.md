# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Changed

- `FieldClassification` now reports the actual matched field candidate through
  `FieldMatchKind`, separately from an allow rule's configured breadth.
- Renamed the runtime package from `qubit-sanitize` to `qubit-redact` and
  separated the procedural macros into the directly consumed
  `qubit-redact-derive` package.
- Reworked the 0.3 API around immutable redaction-policy snapshots, explicit
  allow rules, typed redacted views, checked HTTP body captures, and bounded
  log-safe diagnostics.
- Kept `BodyBudgetError`, `BodyCaptureError`, and `RedactedValue` as closed
  enums so exhaustive matching continues to detect security-relevant semantic
  additions at compile time.

### Added

- Added builder operations to remove exact or suffix allow rules, or clear all
  allow rules, including context-specific HTTP policy builders.
- Added derive support for named, tuple, and unit structs and for named,
  tuple, and unit enum variants across redacted formatting, mutation, and
  serialization.
- Added redacted Serde support for the standard external, internal, adjacent,
  and untagged enum representations through an explicit safe attribute
  allowlist.
- Generalized map redaction to map-like containers with textual keys and
  common `RedactValue` and `RedactValueMut` value types while preserving the
  concrete collection type.
- Added performance baselines for map redaction and structured HTTP bodies.
- Added bounded HTTP body output and hardened diagnostic parsing for URLs,
  forms, JSON, NDJSON, multipart bodies, headers, and malformed input.
- Added `DiagnosticBudget` to bound every public URL, form, text, and header
  diagnostic entry point with a fixed fail-closed marker for oversized input.
- Added borrowed `FieldClassification` explanations while preserving
  `sensitivity_for` precedence and behavior.
- Split redacted Serde expansion into private functional modules without
  changing the derive entry point or generated diagnostics.

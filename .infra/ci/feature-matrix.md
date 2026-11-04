# Feature-matrix design

The feature matrix tests Cargo feature boundaries that can change compilation, public APIs, or behavior. It is intentionally a curated set, not the Cartesian product of every feature flag. A matrix entry is retained when it covers a distinct boundary or interaction; adding a combination requires identifying that coverage.

## Feature relationships

The crate exposes six optional features: `derive`, `serde`, `bigdecimal`, `json`, `http`, and `uri`. Their dependency implications are:

- `bigdecimal` enables `serde`.
- `json` enables `serde`.
- `http` enables `json`, which enables `serde`.
- `derive` and `uri` are independent of those integration chains.

These features represent separately selectable capabilities or optional dependencies, so the CI reduction does not merge or remove public features.

## Selected combinations

| Matrix entry | Feature selection | Commands | Coverage reason |
| --- | --- | --- | --- |
| `derive` | Derive crate, all its features | check, test, doc, clippy | Fully validates the proc-macro crate. |
| `core` | Runtime crate, no features | check, test, doc, clippy | Protects the empty-default build and code compiled only when integrations are absent. |
| `derive-core` | `derive` | check, test | Covers the runtime crate's derive-only path. |
| `serde` | `serde` | check, test | Covers Serde without JSON or other integrations. |
| `derive-serde` | `derive`, `serde` | test | Exercises the derive-plus-Serde API and its compile-contract tests. |
| `derive-json` | `derive`, `json` (implies `serde`) | test | Exercises derive behavior with JSON-specific APIs and projections. |
| `bigdecimal` | `bigdecimal` (implies `serde`) | test | Covers BigDecimal serialization and redaction behavior. |
| `http` | `http` (implies `json`, `serde`) | test | Covers HTTP integration with its required JSON stack. |
| `uri` | `uri` | test, doc | Covers URI support and Rustdoc independently. |
| `http-uri` | `http`, `uri` (and implied `json`, `serde`) | test | Covers joint HTTP/URI formatting and policy paths. |
| `json-arbitrary-precision` | `derive`, `http`, `serde_json/arbitrary_precision` | test | Preserves the targeted arbitrary-precision JSON behavior check. |
| `all-root` | All workspace features | check, test, doc, clippy | Detects integration failures that appear only when capabilities are enabled together. |

## Why the matrix is smaller than the feature space

Feature flags are additive: enabling a feature cannot turn off another feature's code. The matrix therefore protects two important extremes separately: the no-feature build catches accidental dependency on optional code, while `all-root` checks that all integrations coexist. Focused entries cover isolated integrations and source paths that need specific pairs, notably `derive + serde`, `derive + json`, and `http + uri`.

Most former combinations did not correspond to a unique `cfg` path or a separately documented behavior. Running `check`, `test`, `doc`, and `clippy` for every such combination repeated expensive integration and compile-fail tests. The selected matrix keeps full static and documentation checks on the two boundary configurations, and runs tests on the configurations with distinct feature behavior.

When adding a feature or matrix entry, first identify its dependency implications and the `cfg` branches, API contract, or behavior that is not covered by existing entries. Add a combination only for a distinct gap. If a failure concerns only one test family, prefer a targeted command for that family over another full matrix entry.

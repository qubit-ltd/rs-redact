# qubit-redact Design

[中文设计文档](design.zh_CN.md) · [User Guide](user_guide.md) · [README](../README.md)

## 1. Goals and boundaries

`qubit-redact` provides policy-driven, resource-bounded redaction for logs,
errors, and support diagnostics. It handles fields, domain objects, JSON, URI,
HTTP, environment variables, argv, and process descriptions. With redaction
enabled, every published `Complete`, `Truncated`, or `Exhausted` result must
exclude source values that were not approved for publication.

The crate does not erase memory, mutate source objects, or protect output that
bypasses its runtime. Field sensitivity is downstream domain knowledge: domain
models must identify sensitive fields explicitly instead of relying on guesses
from Rust types or current values.

## 2. Core invariants

1. `Redactor` owns an immutable `Arc<RedactionPolicy>` snapshot. Existing
   objects do not observe later application-default replacements.
2. Every composer, batch, or inspection owns an independent transaction and
   budget ledger.
3. Parser errors, input truncation, and budget exhaustion fail closed while
   redaction is enabled.
4. Sensitivity is resolved before lazy value access or formatting.
5. Depth, nodes, collection items, input bytes, JSON values, and output bytes
   are charged to the same transaction.
6. Only a completed transaction constructs public summaries. Parsers and
   format executors never publish a second result model.
7. `RedactionPolicy::disabled()` is an explicit debugging escape hatch that
   restores source values; downstream code owns authorization and timing.

## 3. Architecture

```text
caller
  │
  ▼
Redactor + immutable RedactionPolicy snapshot
  ├── RedactedTextComposer ── TextSession ──► RedactionTextOutput
  ├── RedactionBatch ──────── BatchSession ─► RedactionBatchOutput + handles
  └── inspect_* ───────────── InspectionSession ─► RedactionInspectionResult
                                  │
                                  ▼
                    RuntimeCore: budget, summary, phase
                                  │
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
              domain           formats          output
       RedactionWriter       JSON/HTTP/...   escaping and markers
```

Source responsibilities are:

- `facade`: public entry points, composer, batch, output, and summaries;
- `policy`: field and context rules, masks, and resource limits;
- `runtime`: shared transaction state, budgets, structural admission, sinks,
  and publication;
- `domain`: `Redact`, `RedactionWriter`, container adapters, and optional Serde
  bridges;
- `formats`: argv, env, process, JSON, URI, and HTTP parsing and rendering;
- `output`: log escaping, masked text, and completion states.

The façade, domain, and format layers depend on runtime and policy. Runtime is
independent of the public façade operation model. Formats return internal
`RenderedOperation` values, and the parent transaction is the only publisher.

## 4. Policy model

`RedactionPolicy` combines field rules, masks, format policy, and
`RedactionLimits`. `standard()` is deterministic, `strict()` treats unknown
fields as `Secret`, and `disabled()` explicitly disables confidentiality
redaction.

Field resolution applies base rules before HTTP header/query/body context
rules. Context may strengthen sensitivity but cannot weaken an already stronger
base decision. The shared `ResolvedField::stronger` implementation owns this
security rule so formats do not duplicate it.

`Redactor::application_default()` reads a snapshot from the process-wide slot.
`replace_application_default()` replaces that slot linearly and returns the
previous value. Existing redactors, composers, and batches retain their prior
snapshot.

## 5. Transaction and publication models

### 5.1 Composer

`RedactedTextComposer` appends literals and redacted operations in order.
`literal` accepts only `&'static str`; dynamic data must use a redaction
operation. Consuming `finish(self)` publishes one `RedactionTextOutput`.

### 5.2 Batch

`RedactionBatch` creates independently resolvable items under one shared
budget. Each operation returns a handle valid only for that batch. After
`finish(self)`, `RedactionBatchOutput::resolve()` returns the item text and
summary. The output also retains an aggregate summary. Transaction identity
prevents cross-batch handle resolution.

### 5.3 Inspection

Inspection reuses policy and structural budgets while recording classification,
sensitivity, usage, and incomplete reasons without publishing raw values. An
inspection error means the conclusion is incomplete and must be treated as
sensitive when inspection controls a security decision.

### 5.4 RuntimeCore

`RuntimeCore` stores the policy snapshot, `RedactionBudget`, aggregate
`SummaryBuilder`, transaction phase, and optional item summary. `TextSession`,
`BatchSession`, and `InspectionSession` provide different publication models on
top. Operation sinks commit format results to the parent transaction instead of
creating child budgets or summaries.

## 6. Admission, budgeting, rendering, and publication

Structured operations use one pipeline:

```text
validate metadata
  → budget preflight
  → structural admission / parse once
  → policy resolution
  → bounded rendering and log escaping
  → record usage/reason/completion
  → publish through the parent transaction
```

Preflight happens before advancing untrusted iterators. JSON text is parsed once
during admission into an admitted tree. HTTP JSON, NDJSON, and multipart paths
also reuse admitted structures, preventing inspection and rendering from
producing different parse results.

When output space is insufficient, the runtime retains only complete UTF-8
prefixes and safe markers. `Truncated` means a safe but incomplete
representation remains; `Exhausted` means the budget could not retain a full
replacement. Callers read `RedactionSummary` and must not infer reasons by
parsing marker text.

## 7. Domain objects and Serde

`Redact::write_redacted` writes only through the active `RedactionWriter`.
The writer supports records, sequences, maps, nested values, explicit
sensitivity, runtime-key classification, JSON values, and explicit skips. Every
scope shares the parent budget; depth or collection rejection closes that scope
without opening another output path.

The `derive` feature exports `#[derive(Redact)]`; generated serialization
adapters additionally require `serde`. Internal sealed capability traits cover
scalars, options, references, common containers, tuples, maps, and JSON
ownership forms without exposing implementation details. The internally tagged
serializer accepts only map and struct shapes that preserve the intended
structure; unsupported Serde shapes return explicit errors.

## 8. Format layer

- argv/env/process: explicit classification and bounded heuristics, with
  fail-closed non-UTF-8 handling;
- JSON: one parse, recursive field classification, explicit number ranges, and
  shared structural limits;
- URI: `fluent-uri` parsing with separate identity, path, query, and fragment
  handling;
- HTTP: URL, headers, and bodies, always returning to the parent transaction.

HTTP body implementation is split by responsibility:

- `redaction/body.rs`: admission dispatch and final publication;
- `json_body.rs`: JSON and NDJSON;
- `form_body.rs`: `application/x-www-form-urlencoded`;
- `multipart_body.rs`: multipart parts, nested content types, and file data;
- `text_body.rs`: text, binary, and unsupported fallbacks;
- `url.rs`: URL, nested URL, and query processing;
- `headers.rs`: header rendering;
- `diagnostics.rs`: bounded diagnostic text and completion.

These modules share a private `HttpPolicyExecutor`. It borrows the parent
session policy, owns no session, and produces no public HTTP result. Invalid
content types, missing multipart boundaries, invalid JSON/NDJSON, and truncated
input use safe markers with structured reasons.

## 9. Features and compatibility

The default feature set is empty:

- `derive`: derive macro;
- `serde`: domain serialization adapters and bigdecimal support;
- `json`: Serde JSON and `qubit-json`;
- `http`: includes `json` and adds HTTP, URL, form, and multipart support;
- `uri`: URI support through `fluent-uri`.

Public entry points live in `Redactor`, composer, batch, inspection, policy, and
the domain writer. Format executors, admitted trees, runtime sessions, and sinks
remain crate-private so implementation splitting does not alter the 0.5 public
API.

## 10. Verification strategy

Quality gates use no file exemptions. Unit and integration tests cover public
policy builders, limits, domain writers, sealed capabilities, Serde shapes,
normal and fail-closed format paths, and composer/batch/inspection publication
contracts. Coverage requires at least 95% of functions and strictly more than
90% of both lines and regions.

Fuzz targets cover direct URI/URL input, command input, mixed transaction
sequences, JSON text, HTTP bodies, and multipart bodies. Fixed-secret assertions
check non-disclosure; arbitrary-byte paths check determinism, valid UTF-8 output,
and panic freedom. CI also runs formatting, style, Clippy, tests, rustdoc, and
doctests.

## 11. Deliberate non-goals

- inferring domain sensitivity automatically;
- exposing a formatter or forgeable summary outside transactions;
- zeroizing source memory;
- turning `disabled()` into an authorization system;
- creating HTTP- or JSON-specific public output models;
- traversing untrusted input after exhaustion merely to improve diagnostics.

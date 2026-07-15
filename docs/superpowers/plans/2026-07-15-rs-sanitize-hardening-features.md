# rs-sanitize 安全加固与 Feature 分层 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复已确认的脱敏安全缺陷，提供默认拒绝的不透明文本策略，并以 `core`、`web`、`http` 三类 feature 缩小下游依赖面。

**Architecture:** 保持字段策略为 core 的唯一通用模型；HTTP 文本行为由
`HttpBodySanitizer` 持有的 `TextBodyPolicy` 控制。URL-encoded form 的解析/序列化
抽成 crate-private helper，让 web 与 HTTP 各自按 feature 独立依赖 `form_urlencoded`。

**Tech Stack:** Rust 2024、Cargo features、`http`、`serde_json`、`url`、
`form_urlencoded`、`proptest`。

## Global Constraints

- 只修改 `rs-sanitize`，不修改下游 crate。
- 默认 feature 必须保持当前完整公开 API；feature 名仅为 `core`、`web`、`http`。
- `TextBodyPolicy` 默认 `Redact`，`PassThrough` 仅由调用方显式选择。
- 测试置于 `tests/`，每个生产行为先有失败测试；不提交 git。
- 所有新增公开 API 提供英文 Rustdoc；`README.md` 和 `README.zh_CN.md` 同步说明。

---

### Task 1: 为两处已复现缺陷建立红灯回归测试

**Files:**
- Modify: `tests/core/mask_policy_tests.rs`
- Modify: `tests/adapter/http/http_body_sanitizer_tests.rs`

**Interfaces:**
- Consumes: `MaskPolicy::preserve_edges`, `HttpBodySanitizer::sanitize_body`。
- Produces: 两个失败测试，精确描述极值掩码和显式 Content-Type 的期望行为。

- [ ] **Step 1: 写入掩码极值回归测试**

```rust
#[test]
fn test_mask_policy_preserve_edges_masks_when_edge_lengths_overflow() {
    let policy = MaskPolicy::preserve_edges(usize::MAX, 1, "****", 0);
    let sanitized = policy.mask("secret-token");

    assert_eq!(sanitized, "****");
    assert!(!sanitized.contains("secret-token"));
}
```

- [ ] **Step 2: 运行测试确认旧实现失败**

Run: `cargo test --release --test core_tests test_mask_policy_preserve_edges_masks_when_edge_lengths_overflow`

Expected: FAIL；release 输出包含原始 `secret-token`。

- [ ] **Step 3: 写入显式 Content-Type 回归测试**

```rust
#[test]
fn test_http_body_sanitizer_sanitize_body_respects_explicit_text_content_type() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("text/plain");

    assert_eq!(
        sanitizer.sanitize_body(
            b"{not json}",
            Some(&content_type),
            NameMatchMode::Exact,
        ),
        "<redacted: text body>",
    );
}
```

另加完整测试：

```rust
#[test]
fn test_http_body_sanitizer_sanitize_body_respects_explicit_form_content_type() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/x-www-form-urlencoded");

    assert_eq!(
        sanitizer.sanitize_body(
            b"{=prefix&password=secret",
            Some(&content_type),
            NameMatchMode::Exact,
        ),
        "%7B=prefix&password=%3Credacted%3E",
    );
}
```

该 body 以 `{` 开头，期望 form 解析路径返回经编码的 password redaction，而不是
invalid JSON marker。

- [ ] **Step 4: 运行测试确认旧实现失败**

Run: `cargo test --test adapter_tests test_http_body_sanitizer_sanitize_body_respects_explicit_text_content_type`

Run: `cargo test --test adapter_tests test_http_body_sanitizer_sanitize_body_respects_explicit_form_content_type`

Expected: FAIL；旧实现分别返回 invalid JSON marker，或不符合 form 期望值。

### Task 2: 最小修复边缘掩码与 JSON sniffing

**Files:**
- Modify: `src/core/mask_policy.rs`
- Modify: `src/adapter/http/http_body_sanitizer.rs`

**Interfaces:**
- Consumes: Task 1 的失败测试。
- Produces: 溢出安全的 edge mask 与仅在 Content-Type 缺失时启用的 JSON sniffing。

- [ ] **Step 1: 修复 edge 长度判断**

将：

```rust
chars.len() <= prefix_chars + suffix_chars
```

改为：

```rust
chars.len() <= prefix_chars.saturating_add(suffix_chars)
```

- [ ] **Step 2: 运行 release 回归测试确认变绿**

Run: `cargo test --release --test core_tests test_mask_policy_preserve_edges_masks_when_edge_lengths_overflow`

Expected: PASS。

- [ ] **Step 3: 修复 JSON sniffing 优先级**

令 `HttpBodySanitizer::is_json_body` 在 `Some(content_type)` 时仅返回
`content_type::is_json(content_type)`；仅当参数为 `None` 时调用
`trim_ascii_whitespace` 并检查 `{`/`[`。

- [ ] **Step 4: 运行 HTTP 回归测试确认变绿**

Run: `cargo test --test adapter_tests test_http_body_sanitizer_sanitize_body_respects_explicit_form_content_type`

Expected: PASS。

Run: `cargo test --test adapter_tests test_http_body_sanitizer_sanitize_body_respects_explicit_text_content_type`

Expected: FAIL；JSON sniffing 已修复，text body 会原样返回，尚未引入 Task 3 的 marker。

### Task 3: 引入默认 Redact 的不透明文本策略

**Files:**
- Create: `src/adapter/http/text_body_policy.rs`
- Modify: `src/adapter/http/redaction_markers.rs`
- Modify: `src/adapter/http/http_body_sanitizer.rs`
- Modify: `src/adapter/http/multipart.rs`
- Modify: `src/adapter/http/mod.rs`
- Modify: `src/adapter/mod.rs`
- Modify: `src/lib.rs`
- Create: `tests/adapter/http/text_body_policy_tests.rs`
- Modify: `tests/adapter/http/http_body_sanitizer_tests.rs`
- Modify: `tests/adapter/http/mod.rs`

**Interfaces:**
- Produces: `pub enum TextBodyPolicy { Redact, PassThrough }` 和
  `HttpBodySanitizer::{text_body_policy, set_text_body_policy, with_text_body_policy}`。
- Consumes: `HttpBodySanitizer::new(FieldSanitizer)`，默认策略必须为 `Redact`。

- [ ] **Step 1: 写入文本策略的失败测试**

覆盖以下断言：

```rust
assert_eq!(TextBodyPolicy::default(), TextBodyPolicy::Redact);
assert_eq!(
    HttpBodySanitizer::default().sanitize_body(
        b"plain text secret",
        Some(&HeaderValue::from_static("text/plain")),
        NameMatchMode::Exact,
    ),
    "<redacted: text body>",
);
```

再用 `.with_text_body_policy(TextBodyPolicy::PassThrough)` 验证完整 body 原样输出，
并验证 preview 在 `Redact` 下保留既有 truncation suffix。将现有 multipart 文本
透传测试改为默认 redaction，并增加 PassThrough 下的原样输出测试。

- [ ] **Step 2: 运行测试确认失败原因正确**

Run: `cargo test --test adapter_tests text_body_policy`

Expected: FAIL；`TextBodyPolicy` 和 builder 方法尚不存在。

- [ ] **Step 3: 实现公开策略与 HTTP body 配置**

在 `text_body_policy.rs` 定义：

```rust
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TextBodyPolicy {
    #[default]
    Redact,
    PassThrough,
}
```

为 `HttpBodySanitizer` 增加 `text_body_policy` 字段；`new` 初始化为 `Redact`；
实现只读 getter、`set_text_body_policy` 和 `with_text_body_policy`。为顶层文本与
multipart 文本新增独立 marker，并在 `Redact` 时返回 marker 与已有 suffix。

- [ ] **Step 4: 运行文本策略测试确认变绿**

Run: `cargo test --test adapter_tests text_body_policy`

Expected: PASS。

- [ ] **Step 5: 运行 HTTP adapter 测试**

Run: `cargo test --test adapter_tests http_body_sanitizer`

Expected: PASS。

### Task 4: 合并 form 逻辑并实现三类 feature 分层

**Files:**
- Modify: `Cargo.toml`
- Create: `src/adapter/form_url_encoded.rs`
- Modify: `src/adapter/form_url_encoded_sanitizer.rs`
- Modify: `src/adapter/http/http_body_sanitizer.rs`
- Modify: `src/adapter/mod.rs`
- Modify: `src/adapter/http/mod.rs`
- Modify: `src/lib.rs`
- Modify: `tests/adapter/mod.rs`
- Modify: `tests/adapter/http/mod.rs`
- Modify: `tests/lib_tests.rs`
- Create: `.rs-ci-cargo-matrix.json`

**Interfaces:**
- Produces: `core`、`web`、`http` feature，并在 root 仅导出已启用 feature 的类型。
- Produces: crate-private `sanitize_form_urlencoded(&FieldSanitizer, &[u8], NameMatchMode) -> String`。

- [ ] **Step 1: 先使独立 HTTP 构建失败**

在 `Cargo.toml` 声明目标 feature：

```toml
[features]
default = ["core", "web", "http"]
core = []
web = ["core", "dep:url", "dep:form_urlencoded"]
http = ["core", "dep:http", "dep:serde_json", "dep:form_urlencoded"]
```

并先保留 HTTP body 对 `url::form_urlencoded` 的旧导入。

Run: `cargo check --no-default-features --features http`

Expected: FAIL；HTTP 独立 feature 不再拥有 `url` crate。

- [ ] **Step 2: 抽取共享 helper 并替换两处调用**

将 parse/serialize loop 提取到 `src/adapter/form_url_encoded.rs`，使用直接可选依赖
`form_urlencoded`。`FormUrlEncodedSanitizer::sanitize_bytes` 和
`HttpBodySanitizer::sanitize_form` 都只委托给该 helper。

- [ ] **Step 3: 用 cfg 收窄模块和导出**

- `core` 控制 `core` 模块、argv、env 及其 root export；
- `web` 控制 URL/form 模块及其 root export；
- `http` 控制 HTTP 模块及其 root export；
- `web`、`http` 都隐含 `core`；共享 form helper 使用
  `#[cfg(any(feature = "web", feature = "http"))]`。

同步为 integration-test module 和 crate export smoke test 添加相同条件编译，确保
单 feature `cargo test` 不会引用未启用的公开类型。

- [ ] **Step 4: 写入并运行 feature matrix**

创建 `.rs-ci-cargo-matrix.json`，包含 `core`、`web`、`http`、`all` 四项；前三项使用
`defaultFeatures: false` 和相应单 feature，运行 check/test/doc；`all` 再运行 Clippy。

Run: `./.rs-ci/cargo-feature-check.sh run-all`

Expected: 每一项通过。

- [ ] **Step 5: 验证 form 行为未回归**

Run: `cargo test --all-features --test adapter_tests form_urlencoded`

Expected: PASS，重复 key、字段顺序和 redaction 的既有断言不变。

### Task 5: 增加性质测试并补全公开文档

**Files:**
- Modify: `Cargo.toml`
- Modify: `tests/core/mask_policy_tests.rs`
- Modify: `tests/adapter/http/http_body_sanitizer_tests.rs`
- Modify: `README.md`
- Modify: `README.zh_CN.md`
- Modify: `src/adapter/http/text_body_policy.rs`
- Modify: `src/adapter/http/http_body_sanitizer.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `proptest` 驱动的 panic/泄露性质验证，以及 feature 和文本策略的使用文档。

- [ ] **Step 1: 写入性质测试**

添加 `proptest = "1.0"` dev-dependency。针对随机的 `prefix_chars`、`suffix_chars`、
非空 replacement 与非空 ASCII value，验证 `PreserveEdges` 不 panic，且输出不等于
原 value。针对任意 `Vec<u8>` 与固定代表性 Content-Type 集合调用
`HttpBodySanitizer::sanitize_body`，验证不 panic。

- [ ] **Step 2: 运行性质测试**

Run: `cargo test --all-features --test core_tests mask_policy_proptest`

Run: `cargo test --all-features --test adapter_tests http_body_sanitizer_proptest`

Expected: PASS。

- [ ] **Step 3: 补齐 Rustdoc**

`TextBodyPolicy` Rustdoc 说明默认 `Redact`、`PassThrough` 的主动风险、适用边界和
不保证扫描业务秘密；`HttpBodySanitizer` 的方法文档说明文本策略。将 crate-level
HTTP doctest 用 `#[cfg(feature = "http")]` 包裹，使 core-only doc 能编译。

- [ ] **Step 4: 同步英文和中文 README**

在两份 README 中增加 feature 表、core-only 依赖示例、默认 `Redact` 的文本行为、
显式 `PassThrough` 示例与风险提示；明确不透明文本和藏在非敏感字段值中的业务秘密
不属于字段名脱敏的保证范围。

- [ ] **Step 5: 运行文档测试**

Run: `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --no-default-features --features core`

Run: `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features`

Run: `cargo test --doc --all-features`

Expected: 全部 PASS。

### Task 6: 完整验证与变更审查

**Files:**
- Review: 所有 Task 1–5 文件。

- [ ] **Step 1: 运行完整功能验证**

Run: `cargo test --all-targets --all-features`

Expected: PASS，所有回归和性质测试通过。

- [ ] **Step 2: 运行静态和格式检查**

Run: `cargo clippy --all-targets --all-features -- -D warnings`

Run: `cargo +nightly-2026-06-05 fmt --all -- --check --config-path ../rs-ci/rustfmt.toml`

Expected: 两项 PASS。

- [ ] **Step 3: 运行项目级检查与覆盖率**

Run: `./style-check.sh`

Run: `COVERAGE_OPEN_HTML=0 ./coverage.sh json`

Expected: PASS，满足 functions >= 100%、lines > 95%、regions > 95% 阈值。

- [ ] **Step 4: 审阅变更范围**

Run: `git --no-pager diff --check`

Run: `git status --short`

Expected: 无空白错误；仅包含本计划的源码、测试、README、feature matrix 和内部设计/计划文档变更。

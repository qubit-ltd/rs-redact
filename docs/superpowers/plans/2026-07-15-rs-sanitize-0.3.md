# rs-sanitize 0.3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 发布前完成 `qubit-sanitize 0.3.0` 的匹配语义、集合 API、feature 简化、文档降诺和直接下游本地路径集成。

**Architecture:** core、argv 和 env 始终编译；web/http 只控制带外部依赖的 adapter。`ExactOrSuffix` 先执行现有规范化精确匹配，再只从分隔符或 camelCase token 边界匹配 suffix。`SensitiveFields::insert` 保持覆盖语义，安全合并使用独立的 `merge_strongest`。

**Tech Stack:** Rust 2024、Cargo features、`url`、`http`、`serde_json`、`form_urlencoded`、`proptest`。

## Global Constraints

- `qubit-sanitize` crate 版本必须是 `0.3.0`。
- 下游依赖版本只能写 `0.3`，不能写 patch 版本号；发布前必须带 `path = "../rs-sanitize"`。
- 不修改 CI、`rs-llmsdk-core`、`rs-platform` 或 `rs-http` 的 `qubit-datatype` 依赖。
- 不扫描 JSON 任意 value、不透明文本或 URL path 中的秘密。
- 不创建 Git commit；每个行为修改都按 RED → GREEN → REFACTOR 执行。
- 测试继续放在 `tests/` 的对应现有测试文件中。

---

### Task 1: ExactOrSuffix token 边界匹配

**Files:**
- Modify: `src/core/field_name.rs`
- Modify: `src/core/field_sanitizer.rs`
- Test: `tests/core/field_sanitizer_tests.rs`

**Interfaces:**
- Produces: `pub(crate) fn canonicalize_field_name_suffixes(name: &str) -> Vec<String>`
- Preserves: `pub fn canonicalize_field_name(name: &str) -> String`

- [ ] **Step 1: 写入无边界误匹配失败测试**

```rust
#[test]
fn test_field_sanitizer_sensitivity_for_name_rejects_unbounded_suffix() {
    let mut fields = SensitiveFields::new();
    fields.insert("key", SensitivityLevel::Low);
    fields.insert("api_key", SensitivityLevel::High);
    let sanitizer = FieldSanitizer::new(FieldSanitizePolicy {
        sensitive_fields: fields,
        mask_policies: MaskPolicies::default(),
    });

    assert_eq!(
        sanitizer.sensitivity_for_name(
            "notapikey",
            NameMatchMode::ExactOrSuffix,
        ),
        None,
    );
    assert_eq!(
        sanitizer.sensitivity_for_name("monkey", NameMatchMode::ExactOrSuffix),
        None,
    );
}
```

- [ ] **Step 2: 运行测试并确认 RED**

Run: `cargo test --locked --test core_tests test_field_sanitizer_sensitivity_for_name_rejects_unbounded_suffix -- --exact`

Expected: FAIL；当前实现分别返回 `Some(High)` 或 `Some(Low)`。

- [ ] **Step 3: 增加 token suffix helper 并接入匹配**

`field_name.rs` 新增私有边界识别和 crate 内 helper。实现必须：

```rust
pub(crate) fn canonicalize_field_name_suffixes(name: &str) -> Vec<String> {
    let chars = name.trim().chars().collect::<Vec<_>>();
    let mut tokens = Vec::<String>::new();
    let mut token = String::new();

    for (index, ch) in chars.iter().copied().enumerate() {
        if is_field_separator(ch) {
            push_token(&mut tokens, &mut token);
            continue;
        }
        let previous = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
        let next = chars.get(index + 1).copied();
        if !token.is_empty() && starts_camel_token(previous, ch, next) {
            push_token(&mut tokens, &mut token);
        }
        token.extend(ch.to_lowercase());
    }
    push_token(&mut tokens, &mut token);

    let mut suffixes = Vec::with_capacity(tokens.len());
    let mut suffix = String::new();
    for token in tokens.into_iter().rev() {
        suffix.insert_str(0, &token);
        suffixes.push(suffix.clone());
    }
    suffixes
}
```

辅助函数必须有英文 Rustdoc，分隔符为 `_`、`-`、`.` 和 Unicode whitespace；camel
边界覆盖 lower/digit → upper 和 acronym → capitalized word。

`FieldSanitizer::sensitivity_for_name` 在精确查询失败后调用该 helper，只接受
`suffixes` 中完整 token suffix，并继续选择最长配置字段。

- [ ] **Step 4: 运行回归测试并确认 GREEN**

Run: `cargo test --locked --test core_tests test_field_sanitizer_sensitivity_for_name_rejects_unbounded_suffix -- --exact`

Expected: PASS。

- [ ] **Step 5: 增加并运行正向边界测试**

测试 `OPENAI_API_KEY`、`openaiApiKey`、`openaiAPIKey`、`openai-api-key` 均匹配
`api_key`，`apiKey` 仍由精确规范化命中，并保留最长 suffix 行为。

Run: `cargo test --locked --test core_tests field_sanitizer_sensitivity_for_name`

Expected: 全部 PASS。

### Task 2: SensitiveFields 集合能力

**Files:**
- Modify: `src/core/sensitive_fields.rs`
- Test: `tests/core/sensitive_fields_tests.rs`

**Interfaces:**
- Produces: `remove`、`clear`、`merge_strongest`、`FromIterator`
- Preserves: `insert` 的后写覆盖语义

- [ ] **Step 1: 为 remove 写失败测试并确认 RED**

```rust
#[test]
fn test_sensitive_fields_remove_uses_canonical_name() {
    let mut fields = SensitiveFields::new();
    fields.insert("api_key", SensitivityLevel::High);

    assert_eq!(fields.remove(" API-Key "), Some(SensitivityLevel::High));
    assert!(fields.is_empty());
    assert_eq!(fields.remove(" -_. "), None);
}
```

Run: `cargo test --locked --test core_tests test_sensitive_fields_remove_uses_canonical_name -- --exact`

Expected: 编译失败，提示缺少 `remove`。

- [ ] **Step 2: 实现 remove 并确认 GREEN**

```rust
pub fn remove(&mut self, field: &str) -> Option<SensitivityLevel> {
    let field = canonicalize_field_name(field);
    if field.is_empty() {
        None
    } else {
        self.fields.remove(&field)
    }
}
```

- [ ] **Step 3: 为 clear 写失败测试、实现并确认 GREEN**

测试清空多个字段后 `len() == 0` 且 `is_empty()`；实现调用 `self.fields.clear()`。

- [ ] **Step 4: 为 strongest merge 写失败测试并确认 RED**

测试 target 的 `authorization: High` 不被 source 的 `Low` 降级，source 的
`password: Secret` 能提高 target 的等级，新字段正常加入。

- [ ] **Step 5: 实现 strongest merge 并确认 GREEN**

```rust
pub fn merge_strongest(&mut self, other: &Self) {
    for (field, level) in other.iter() {
        self.fields
            .entry(field.to_string())
            .and_modify(|current| *current = (*current).max(level))
            .or_insert(level);
    }
}
```

- [ ] **Step 6: 为 FromIterator 写失败测试、实现并确认 GREEN**

测试 `&str` 和 `String` 均可 collect，规范化有效，重复字段最后一项覆盖。实现：

```rust
impl<S> FromIterator<(S, SensitivityLevel)> for SensitiveFields
where
    S: AsRef<str>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (S, SensitivityLevel)>,
    {
        let mut fields = Self::new();
        for (field, level) in iter {
            fields.insert(field.as_ref(), level);
        }
        fields
    }
}
```

Run: `cargo test --locked --test core_tests sensitive_fields`

Expected: 全部相关测试 PASS。

### Task 3: 0.3 版本、始终可用的 core 和公开枚举

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src/lib.rs`
- Modify: `src/adapter/mod.rs`
- Modify: `tests/lib_tests.rs`
- Modify: `tests/adapter/mod.rs`
- Modify: `src/core/sensitivity_level.rs`
- Modify: `src/core/sensitive_field_preset.rs`
- Modify: `src/core/name_match_mode.rs`
- Modify: `src/core/mask_policy.rs`
- Modify: `src/adapter/http/text_body_policy.rs`

**Interfaces:**
- `--no-default-features` 导出 core、argv 和 env
- `web`、`http` 独立控制带外部依赖的 adapter

- [ ] **Step 1: 用 core_tests 确认当前 no-default 构建为 RED**

Run: `cargo test --locked --no-default-features --test core_tests`

Expected: 编译失败，因为 core 导出被关闭。

- [ ] **Step 2: 调整 package 和 features**

```toml
version = "0.3.0"

[features]
default = ["web", "http"]
web = ["dep:form_urlencoded", "dep:url"]
http = ["dep:form_urlencoded", "dep:http", "dep:serde_json"]
```

删除 `src/lib.rs`、`src/adapter/mod.rs`、`tests/lib_tests.rs` 和
`tests/adapter/mod.rs` 中所有 `feature = "core"` gate；保留 web/http gate。

- [ ] **Step 3: 为全部公开枚举增加 non_exhaustive**

在五个公开枚举的 derive 前增加：

```rust
#[non_exhaustive]
```

- [ ] **Step 4: 更新 lockfile 并验证 feature matrix GREEN**

Run:

```text
cargo test --no-default-features --test core_tests
cargo test --no-default-features --test adapter_tests
cargo test --no-default-features --features web --all-targets
cargo test --no-default-features --features http --all-targets
cargo test --all-features --all-targets
```

Expected: 全部 PASS，core-only 不编译 url/http/serde_json。

### Task 4: 跨 adapter no-leak 性质测试

**Files:**
- Modify: `tests/adapter/argv_tests.rs`
- Modify: `tests/adapter/env_tests.rs`
- Modify: `tests/adapter/form_urlencoded_tests.rs`
- Modify: `tests/adapter/url_tests.rs`
- Modify: `tests/adapter/http/http_header_sanitizer_tests.rs`
- Modify: `tests/adapter/http/http_body_sanitizer_tests.rs`

**Interfaces:**
- Consumes: 所有现有公开 adapter
- Produces: 对完整敏感原文不出现在输出中的性质保证

- [ ] **Step 1: 为 argv/env 增加 no-leak property**

每个测试使用 `secret in "[A-Za-z0-9]{8,64}"`。argv 将值放入
`--password <secret>`，env 放入 `OPENAI_API_KEY=<secret>`，使用真实 sanitizer 并
`prop_assert!(!rendered.contains(&secret))`。

- [ ] **Step 2: 为 form/URL/header 增加 no-leak property**

form 使用 `password=<secret>`，URL 使用 `access_token=<secret>`，header 使用
`Authorization: <secret>`。URL 另加确定性测试，确认厂商 token path 原样保留而
query 仍被脱敏。

- [ ] **Step 3: 为 HTTP body 增加结构化 no-leak property**

同一个随机值分别放入：

```text
{"password":"<secret>"}
{"password":"<secret>"}\n
password=<secret>
--boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\n<secret>\r\n--boundary--\r\n
```

分别使用 JSON、NDJSON、form 和 multipart Content-Type，断言每个输出都不包含完整
原值。

- [ ] **Step 4: 运行 adapter property tests**

Run: `cargo test --all-features --test adapter_tests proptest`

Expected: 全部 PASS。

### Task 5: rs-http strongest merge 与本地依赖

**Files:**
- Modify: `../rs-http/Cargo.toml`
- Modify: `../rs-http/Cargo.lock`
- Modify: `../rs-http/src/sanitize/log_sanitizer.rs`
- Test: `../rs-http/tests/options/http_client_options_tests.rs`

**Interfaces:**
- Consumes: `SensitiveFields::merge_strongest`
- Preserves: 用户自定义字段可加入 debug 策略

- [ ] **Step 1: 写入 debug 不可降级回归测试**

构造 `HttpClientOptions`，把 `authorization` 改成 `Low`，加入值
`Bearer downgrade-secret`，断言 Debug 输出包含完全掩码 `****`，且不包含低等级输出
`Be****et`。

- [ ] **Step 2: 用独立临时 consumer 确认 RED**

由于 rs-http 既有 `qubit-datatype ^0.3` dev-dependency 阻止其测试解析，使用只把
rs-http 当普通 path dependency 的临时测试 crate 运行同一公开行为。

Expected: 当前实现断言失败并显示低等级掩码；不得修改 `qubit-datatype`。

- [ ] **Step 3: 替换合并逻辑**

将 `for_debug` 的三个 helper 调用替换为：

```rust
debug_policy
    .sensitive_headers
    .merge_strongest(&policy.sensitive_headers);
debug_policy
    .sensitive_query_params
    .merge_strongest(&policy.sensitive_query_params);
debug_policy
    .sensitive_body_fields
    .merge_strongest(&policy.sensitive_body_fields);
```

删除仅为旧覆盖合并存在的 `extend_sensitive_fields` 私有函数。

- [ ] **Step 4: 调整 rs-http 依赖并验证 GREEN**

```toml
qubit-sanitize = {
    version = "0.3",
    path = "../rs-sanitize",
    default-features = false,
    features = ["web", "http"],
}
```

更新 lockfile，重跑临时 consumer，Expected: PASS。尝试运行 rs-http 定向测试；若仍
在依赖解析阶段失败，记录该既有 blocker。

### Task 6: rs-command core-only 本地依赖

**Files:**
- Modify: `../rs-command/Cargo.toml`
- Modify: `../rs-command/Cargo.lock`

- [ ] **Step 1: 修改依赖声明**

```toml
qubit-sanitize = {
    version = "0.3",
    path = "../rs-sanitize",
    default-features = false,
}
```

- [ ] **Step 2: 更新 lockfile 并检查依赖树**

Run: `cargo tree --locked -p qubit-sanitize`

Expected: `qubit-sanitize v0.3.0` 来源为相对路径，不包含 `url`、`http`、
`serde_json` 或 `form_urlencoded`。

- [ ] **Step 3: 运行 rs-command 完整测试**

Run: `cargo test --locked --all-targets`

Expected: PASS。

### Task 7: 文档降诺和 0.3 使用说明

**Files:**
- Modify: `README.md`
- Modify: `README.zh_CN.md`
- Modify: `src/lib.rs`
- Modify: `src/adapter/url_sanitizer.rs`
- Modify: `src/adapter/http/http_body_sanitizer.rs`
- Modify: `src/adapter/http/http_header_sanitizer.rs`
- Modify: `src/adapter/http/multipart.rs`

- [ ] **Step 1: 更新版本和 feature 示例**

普通依赖示例使用 `qubit-sanitize = "0.3"`；core-only 示例使用：

```toml
qubit-sanitize = { version = "0.3", default-features = false }
```

- [ ] **Step 2: 更新 ExactOrSuffix 和职责边界**

说明 suffix 只从分隔符或 camelCase token 边界开始；明确 `notapikey` 不匹配
`api_key`。说明默认字段集合不是完整秘密词典。

- [ ] **Step 3: 降低 log-safe 承诺**

将相关 Rustdoc 改为“sanitized diagnostic representation/value/URL/body”，明确：

- URL path 原样保留，厂商 webhook/token 由调用方处理；
- 非敏感 JSON 字段、顶层 scalar 和不透明文本不做任意 secret 扫描；
- body 输出不可回放。

- [ ] **Step 4: 检查文档一致性**

Run: `rg -n 'log-safe|version = "0\.2|features = \["core"\]|feature = "core"' README.md README.zh_CN.md src tests Cargo.toml`

Expected: 不再存在过时版本、core feature 或绝对安全承诺；与安全语义无关的类型名不受影响。

### Task 8: 完整验证与交付审查

**Files:**
- Review: `rs-sanitize`、`rs-command`、`rs-http` 的全部本次变更

- [ ] **Step 1: 格式和静态检查**

Run:

```text
cargo +nightly-2026-06-05 fmt --all -- --check --config-path .rs-ci/rustfmt.toml
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps --all-features
```

- [ ] **Step 2: 完整测试与 feature matrix**

Run:

```text
cargo test --all-targets --all-features
cargo test --no-default-features --all-targets
cargo test --no-default-features --features web --all-targets
cargo test --no-default-features --features http --all-targets
```

- [ ] **Step 3: 覆盖率**

Run: `COVERAGE_OPEN_HTML=0 ./coverage.sh json`

Expected: 项目现有 line/region/function 阈值全部通过。

- [ ] **Step 4: 下游验证**

在 `rs-command` 运行完整测试；在 `rs-http` 运行可执行的检查和测试并如实记录既有
依赖 blocker。不得因 blocker 修改超出范围的依赖。

- [ ] **Step 5: diff 和需求逐项审查**

分别在三个仓库运行 `git status --short`、`git --no-pager diff --check` 和
`git --no-pager diff`。确认没有 CI、llmsdk、platform 或无关文件变更，且版本约束、
相对路径、API、文档和测试全部覆盖设计要求。

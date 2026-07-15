# rs-sanitize 0.3 Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在首次发布 `qubit-sanitize 0.3.0` 前完成结构化 HTTP body 结果、policy API 私有化、安全默认、multipart 歧义处理、下游迁移和版本依赖图收口。

**Architecture:** `rs-sanitize` 继续以 core policy 和协议 adapter 分层；HTTP body 返回结构化诊断结果，由 `Display` 负责标准 marker。`rs-http` 通过领域 policy facade 和结构化 metadata 集成，`rs-command` 复用 core 的安全 Debug wrapper。版本与锁文件在行为稳定后从依赖链底部向上更新。

**Tech Stack:** Rust 2024/2021、Cargo features、`http 1.4`、`url 2.5`、`serde_json 1.0`、`form_urlencoded 1.2`、`proptest`、项目 `.rs-ci` 脚本。

## Global Constraints

- 设计规格：`docs/superpowers/specs/2026-07-15-rs-sanitize-0.3-release-hardening-design.md`。
- `qubit-sanitize` 保持 `0.3.0`；`qubit-http` 保持 `0.10.0`；`qubit-command` 升到 `0.5.0`；`qubit-mime` 升到 `0.9.1`；`qubit-magika` 保持 `0.8.0`。
- `qubit-value` 保持 `0.10.0`，为 `qubit-datatype` 补同仓库 path；`qubit-config`
  保持 `0.14.0` 并验证本地依赖类型身份唯一。
- Rust MSRV 保持 `1.94`；不新增第三方依赖。
- 不修改 `rs-platform` 和存在用户改动的 `rs-llmsdk-core`。
- 不扫描任意文本、任意 JSON value 或 URL path；不改变真实业务值和请求值。
- Rustdoc 继续使用项目现有 `# Parameters`，不改成 `# Arguments`。
- 所有功能行为严格执行 RED → GREEN → REFACTOR；配置、锁文件、文档和纯文件移动通过专用命令验证。
- 测试全部保留在 `tests/`，禁止在源码内增加 inline test module。
- 不执行 `git add`、`git commit` 或 `git push`；每个 task 结束只做只读 diff 检查。
- 修改多个仓库时分别检查 diff，禁止把不同仓库的变更混为一个提交单元。

---

### Task 1: 修复 Cargo feature matrix

**Files:**
- Modify: `rs-sanitize/.rs-ci-cargo-matrix.json`
- Verify: `rs-sanitize/Cargo.toml`

**Interfaces:**
- Consumes: `Cargo.toml` 中唯一可选 features `web`、`http`
- Produces: core/web/http/all 四个有效验证组合

- [ ] **Step 1: 记录当前配置错误**

Run from `rs-sanitize`:

```bash
rg -n '"core"|"allFeatures"|"features"' .rs-ci-cargo-matrix.json Cargo.toml
```

Expected: matrix 的 core/all 行仍包含不存在的 `core` feature，而 `Cargo.toml` 不定义它。

- [ ] **Step 2: 改正 matrix**

将 core 和 all 两项改为：

```json
{
  "name": "core",
  "commands": ["check", "test", "doc"],
  "defaultFeatures": false,
  "features": []
},
{
  "name": "all",
  "commands": ["check", "test", "doc", "clippy"],
  "allFeatures": true
}
```

web、http 两项保持现有配置。

- [ ] **Step 3: 验证四个组合能够启动**

```bash
cargo check --locked --no-default-features
cargo check --locked --no-default-features --features web
cargo check --locked --no-default-features --features http
cargo check --locked --all-features
```

Expected: 四条命令 exit 0，不出现 `package does not contain this feature: core`。

- [ ] **Step 4: 检查 task diff**

```bash
git --no-pager diff -- .rs-ci-cargo-matrix.json
git diff --check
```

Expected: 只包含 matrix 修复且无 whitespace error。

### Task 2: 收口 core policy 与 strongest mutation API

**Files:**
- Modify: `rs-sanitize/src/core/sensitivity_level.rs`
- Modify: `rs-sanitize/src/core/mask_policies.rs`
- Modify: `rs-sanitize/src/core/field_sanitize_policy.rs`
- Modify: `rs-sanitize/src/core/sensitive_fields.rs`
- Modify: `rs-sanitize/src/core/field_sanitizer.rs`
- Test: `rs-sanitize/tests/core/mask_policy_tests.rs`
- Test: `rs-sanitize/tests/core/sensitive_fields_tests.rs`
- Test: `rs-sanitize/tests/core/field_sanitizer_tests.rs`

**Interfaces:**
- Produces: `MaskPolicies::{new, for_level_mut, set, with_policy}`
- Produces: private `FieldSanitizePolicy` fields plus constructors/accessors/builders
- Produces: `SensitiveFields::{insert_strongest, extend_strongest}`
- Produces: strongest `FieldSanitizer::{insert_sensitive_field, extend_sensitive_fields}` and explicit `set_sensitive_field_level`

- [ ] **Step 1: 写 strongest 与 policy API 失败测试**

在对应 core tests 增加：

```rust
#[test]
fn test_sensitive_fields_insert_strongest_never_lowers_existing_level() {
    let mut fields = SensitiveFields::new();
    fields.insert("password", SensitivityLevel::Secret);

    fields.insert_strongest("Password", SensitivityLevel::Low);

    assert_eq!(fields.level_for("password"), Some(SensitivityLevel::Secret));
}

#[test]
fn test_field_sanitizer_add_and_set_have_distinct_level_semantics() {
    let mut sanitizer = FieldSanitizer::default();

    sanitizer.insert_sensitive_field("password", SensitivityLevel::Low);
    assert_eq!(
        sanitizer.sensitivity_for_name("password", NameMatchMode::Exact),
        Some(SensitivityLevel::Secret),
    );

    sanitizer.set_sensitive_field_level("password", SensitivityLevel::Low);
    assert_eq!(
        sanitizer.sensitivity_for_name("password", NameMatchMode::Exact),
        Some(SensitivityLevel::Low),
    );
}

#[test]
fn test_mask_policies_set_and_builder_update_requested_level() {
    let mut policies = MaskPolicies::default();
    policies.set(SensitivityLevel::High, MaskPolicy::fixed("<high>"));
    assert_eq!(
        policies.for_level(SensitivityLevel::High).mask("secret"),
        "<high>",
    );

    let policies = policies.with_policy(
        SensitivityLevel::Secret,
        MaskPolicy::fixed("<secret>"),
    );
    assert_eq!(
        policies.for_level(SensitivityLevel::Secret).mask("secret"),
        "<secret>",
    );
}
```

- [ ] **Step 2: 运行测试并确认 RED**

```bash
cargo test --locked --test core_tests insert_strongest
cargo test --locked --test core_tests add_and_set_have_distinct
cargo test --locked --test core_tests mask_policies_set_and_builder
```

Expected: 编译失败，缺少新 API。

- [ ] **Step 3: 实现 MaskPolicies 私有字段 API**

字段改为私有，并实现：

```rust
impl MaskPolicies {
    pub const fn new(
        low: MaskPolicy,
        medium: MaskPolicy,
        high: MaskPolicy,
        secret: MaskPolicy,
    ) -> Self {
        Self { low, medium, high, secret }
    }

    #[inline]
    pub fn for_level_mut(
        &mut self,
        level: SensitivityLevel,
    ) -> &mut MaskPolicy {
        match level {
            SensitivityLevel::Low => &mut self.low,
            SensitivityLevel::Medium => &mut self.medium,
            SensitivityLevel::High => &mut self.high,
            SensitivityLevel::Secret => &mut self.secret,
        }
    }

    #[inline]
    pub fn set(&mut self, level: SensitivityLevel, policy: MaskPolicy) {
        *self.for_level_mut(level) = policy;
    }

    #[inline]
    pub fn with_policy(
        mut self,
        level: SensitivityLevel,
        policy: MaskPolicy,
    ) -> Self {
        self.set(level, policy);
        self
    }
}
```

保留 `for_level`，补 `#[inline]`。`SensitivityLevel` Rustdoc 明确
`Low < Medium < High < Secret`。

- [ ] **Step 4: 实现 FieldSanitizePolicy 私有字段 API**

```rust
impl FieldSanitizePolicy {
    pub const fn new(
        sensitive_fields: SensitiveFields,
        mask_policies: MaskPolicies,
    ) -> Self {
        Self { sensitive_fields, mask_policies }
    }

    #[inline]
    pub const fn sensitive_fields(&self) -> &SensitiveFields {
        &self.sensitive_fields
    }

    #[inline]
    pub fn sensitive_fields_mut(&mut self) -> &mut SensitiveFields {
        &mut self.sensitive_fields
    }

    #[inline]
    pub const fn mask_policies(&self) -> &MaskPolicies {
        &self.mask_policies
    }

    #[inline]
    pub fn mask_policies_mut(&mut self) -> &mut MaskPolicies {
        &mut self.mask_policies
    }

    #[inline]
    pub fn with_sensitive_fields(mut self, fields: SensitiveFields) -> Self {
        self.sensitive_fields = fields;
        self
    }

    #[inline]
    pub fn with_mask_policies(mut self, policies: MaskPolicies) -> Self {
        self.mask_policies = policies;
        self
    }
}
```

`empty` 和 `Default` 使用 `Self::new(...)`。

- [ ] **Step 5: 实现 strongest 与显式 set**

```rust
pub fn insert_strongest(&mut self, field: &str, level: SensitivityLevel) {
    let field = canonicalize_field_name(field);
    if field.is_empty() {
        return;
    }
    self.fields
        .entry(field)
        .and_modify(|current| *current = (*current).max(level))
        .or_insert(level);
}

pub fn extend_strongest<I, S>(&mut self, fields: I, level: SensitivityLevel)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    for field in fields {
        self.insert_strongest(field.as_ref(), level);
    }
}
```

`FieldSanitizer` 的 add facade 调用上述方法；新增：

```rust
pub fn set_sensitive_field_level(
    &mut self,
    field: &str,
    level: SensitivityLevel,
) {
    self.policy.sensitive_fields_mut().insert(field, level);
}
```

其余字段读取全部改用 policy accessors。

- [ ] **Step 6: 迁移 rs-sanitize 内部 struct literal**

把测试和源码中的：

```rust
FieldSanitizePolicy {
    sensitive_fields: fields,
    mask_policies: policies,
}
```

改为：

```rust
FieldSanitizePolicy::new(fields, policies)
```

把 `MaskPolicies { ... }` 改为 `MaskPolicies::new(low, medium, high, secret)`。

- [ ] **Step 7: 运行 core tests 并确认 GREEN**

```bash
cargo test --locked --test core_tests
```

Expected: 全部 core tests PASS。

### Task 3: 新增 BodySanitization 结构化结果类型骨架

**Files:**
- Create: `rs-sanitize/src/adapter/http/body_redaction_reason.rs`
- Create: `rs-sanitize/src/adapter/http/body_sanitization_status.rs`
- Create: `rs-sanitize/src/adapter/http/body_sanitization.rs`
- Modify: `rs-sanitize/src/adapter/http/mod.rs`
- Modify: `rs-sanitize/src/lib.rs`
- Create: `rs-sanitize/tests/adapter/http/body_sanitization_tests.rs`
- Modify: `rs-sanitize/tests/adapter/http/mod.rs`
- Modify: `rs-sanitize/tests/lib_tests.rs`

**Interfaces:**
- Produces: `BodyRedactionReason`, `BodySanitizationStatus`, `BodySanitization`
- Produces: 设计规格中的三个公开类型；构造与行为在 Task 4 通过 sanitizer 公共 API 驱动实现

- [ ] **Step 1: 写公开类型失败测试**

```rust
use qubit_sanitize::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
};

#[test]
fn test_body_sanitization_types_are_public() {
    let status = BodySanitizationStatus::Redacted(
        BodyRedactionReason::InvalidOrTruncatedJson,
    );
    assert_eq!(
        status,
        BodySanitizationStatus::Redacted(
            BodyRedactionReason::InvalidOrTruncatedJson,
        ),
    );
    let _: Option<BodySanitization> = None;
}
```

- [ ] **Step 2: 运行测试并确认 RED**

```bash
cargo test --locked --features http --test adapter_tests body_sanitization
```

Expected: 编译失败，公开类型尚不存在。

- [ ] **Step 3: 实现三个公开类型骨架**

`BodyRedactionReason`、`BodySanitizationStatus` 和核心 struct 按设计规格定义：

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySanitization {
    content: String,
    status: BodySanitizationStatus,
    captured_len: usize,
    source_len: usize,
}
```

每个公开类型、variant 和字段补齐英文 Rustdoc。此阶段不增加设计规格之外的 public
constructor，也不提前实现 accessor/渲染行为。

- [ ] **Step 4: 导出类型并确认 GREEN**

在 HTTP module 和 crate root 的 `#[cfg(feature = "http")]` 重导出三个类型；
`tests/lib_tests.rs` 增加类型可见性断言。

```bash
cargo test --locked --features http --test adapter_tests body_sanitization
cargo test --locked --features http --test lib_tests
```

Expected: 新测试 PASS。

### Task 4: 实现 BodySanitization 行为并迁移 HttpBodySanitizer

**Files:**
- Modify: `rs-sanitize/src/adapter/http/http_body_sanitizer.rs`
- Modify: `rs-sanitize/src/adapter/http/body_input_kind.rs`（随后在 Task 7 移动）
- Modify: `rs-sanitize/tests/adapter/http/http_body_sanitizer_tests.rs`
- Modify: `rs-sanitize/tests/adapter/http/body_sanitization_tests.rs`
- Modify: `rs-sanitize/tests/adapter/http/text_body_policy_tests.rs`
- Modify: `rs-sanitize/README.md`
- Modify: `rs-sanitize/README.zh_CN.md`

**Interfaces:**
- Consumes: Task 3 的 `BodySanitization` 类型
- Produces: `sanitize_body`、`sanitize_body_preview` 返回 `BodySanitization`

- [ ] **Step 1: 写 sanitizer metadata 与渲染失败测试**

```rust
#[test]
fn test_http_body_sanitizer_preview_returns_structured_redaction_metadata() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let prefix = br#"{"password":"secret"#;

    let result = sanitizer.sanitize_body_preview(
        prefix,
        40,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        result.status(),
        BodySanitizationStatus::Redacted(
            BodyRedactionReason::InvalidOrTruncatedJson,
        ),
    );
    assert_eq!(result.captured_len(), prefix.len());
    assert_eq!(result.source_len(), 40);
    assert_eq!(result.truncated_bytes(), 40 - prefix.len());
    assert!(!result.content().contains("secret"));
    assert_eq!(
        result.to_string(),
        format!(
            "<redacted: invalid or truncated JSON>...<truncated {} bytes>",
            40 - prefix.len(),
        ),
    );
    assert_eq!(result.rendered(), result.to_string());
}
```

- [ ] **Step 2: 运行测试并确认 RED**

```bash
cargo test --locked --features http --test adapter_tests preview_returns_structured
```

Expected: 当前返回 `String`，没有 metadata methods；结构化类型也尚未实现这些方法。

- [ ] **Step 3: 改造 HttpBodySanitizer 返回类型**

先为 `BodySanitization` 实现设计规格中的 accessors、`Display`、`rendered` 和
`into_rendered`。内部构造器保持 `pub(super)`，不扩大公开 API：

```rust
pub(super) fn new(
    content: String,
    status: BodySanitizationStatus,
    captured_len: usize,
    source_len: usize,
) -> Self {
    Self {
        content,
        status,
        captured_len,
        source_len: source_len.max(captured_len),
    }
}
```

`sanitize_body_inner` 的每条 return 都通过该内部构造器生成结果。

状态映射必须是：

```text
empty                         -> Empty
valid JSON/NDJSON/form        -> Sanitized
valid multipart summary       -> Sanitized
TextBodyPolicy::PassThrough   -> Sanitized
TextBodyPolicy::Redact        -> Redacted(OpaqueText)
invalid complete JSON         -> Redacted(InvalidJson)
invalid preview JSON          -> Redacted(InvalidOrTruncatedJson)
invalid complete NDJSON       -> Redacted(InvalidNdjson)
invalid preview NDJSON        -> Redacted(InvalidOrTruncatedNdjson)
invalid multipart             -> Redacted(InvalidMultipart)
truncated multipart preview   -> Redacted(TruncatedMultipart)
invalid Content-Type          -> Redacted(InvalidContentType)
unsupported UTF-8 body        -> Redacted(UnsupportedMediaType)
non-UTF-8 body                -> Binary
```

`content` 不再拼接 truncation suffix。空 preview 的 content 为 `<empty>`；空完整 body
的 content 为空字符串。binary content 保持 `<binary N bytes>`。

- [ ] **Step 4: 迁移现有 rs-sanitize body tests**

字符串断言统一显式渲染：

```rust
let result = sanitizer.sanitize_body(...);
assert_eq!(result.to_string(), expected);
assert!(!result.to_string().contains(secret));
```

需要多次使用时先保存：

```rust
let rendered = result.to_string();
assert_eq!(rendered, expected);
assert!(!rendered.contains(secret));
```

proptest 同样对 `result.to_string()` 做 no-leak 断言。

- [ ] **Step 5: 运行 HTTP adapter tests 并确认 GREEN**

```bash
cargo test --locked --features http --test adapter_tests http_body_sanitizer
cargo test --locked --features http --test adapter_tests text_body_policy
```

Expected: 当前 marker 文案保持，新增 metadata 断言 PASS。

### Task 5: URL password、security_key 和 RedactedDebug

**Files:**
- Modify: `rs-sanitize/src/adapter/url_sanitizer.rs`
- Modify: `rs-sanitize/src/core/sensitive_field_preset.rs`
- Create: `rs-sanitize/src/core/redacted_debug.rs`
- Modify: `rs-sanitize/src/core/mod.rs`
- Modify: `rs-sanitize/src/lib.rs`
- Modify: `rs-sanitize/tests/adapter/url_tests.rs`（Task 7 后改名）
- Modify: `rs-sanitize/tests/core/sensitive_field_preset_tests.rs`
- Create: `rs-sanitize/tests/core/redacted_debug_tests.rs`
- Modify: `rs-sanitize/tests/core/mod.rs`
- Modify: `rs-sanitize/tests/lib_tests.rs`

**Interfaces:**
- Produces: URL password 使用 `Secret`
- Produces: `security_key -> Secret`
- Produces: `RedactedDebug<'a, T>` 与 `redacted_debug(&T)`

- [ ] **Step 1: 写三个失败测试**

```rust
#[test]
fn test_url_sanitizer_uses_secret_policy_for_password() {
    let mut policies = MaskPolicies::default();
    policies.set(
        SensitivityLevel::High,
        MaskPolicy::preserve_edges(1, 1, "****", 0),
    );
    policies.set(
        SensitivityLevel::Secret,
        MaskPolicy::fixed("SECRET_MASK"),
    );
    let sanitizer = UrlSanitizer::new(FieldSanitizer::new(
        FieldSanitizePolicy::default().with_mask_policies(policies),
    ));

    let sanitized = sanitizer
        .sanitize_url_str(
            "https://alice:password@example.test/path#fragment",
            NameMatchMode::Exact,
        )
        .expect("URL should parse");

    let sanitized = Url::parse(&sanitized).expect("sanitized URL should parse");
    assert_eq!(sanitized.username(), "a****e");
    assert_eq!(sanitized.password(), Some("SECRET_MASK"));
    assert_eq!(sanitized.fragment(), Some("f****t"));
    assert!(!sanitized.as_str().contains("password"));
}

#[test]
fn test_credentials_preset_contains_security_key_as_secret() {
    let fields = SensitiveFields::default();
    assert_eq!(
        fields.level_for("security_key"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_redacted_debug_never_calls_inner_debug() {
    struct PanicDebug;
    impl std::fmt::Debug for PanicDebug {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("inner Debug must not be called");
        }
    }

    assert_eq!(format!("{:?}", redacted_debug(&PanicDebug)), "<redacted>");
}
```

- [ ] **Step 2: 分别运行并确认 RED**

```bash
cargo test --locked --features web --test adapter_tests uses_secret_policy
cargo test --locked --test core_tests security_key_as_secret
cargo test --locked --test core_tests redacted_debug
```

Expected: URL 测试显示 High mask；preset 不含字段；wrapper 尚不存在。

- [ ] **Step 3: 区分 URL 结构字段等级**

```rust
fn mask_url_component(
    sanitizer: &FieldSanitizer,
    value: &str,
    level: SensitivityLevel,
) -> String {
    sanitizer
        .policy()
        .mask_policies()
        .for_level(level)
        .mask(value)
        .into_owned()
}
```

username/fragment 传 `High`，password 传 `Secret`。

- [ ] **Step 4: 增加 security_key preset**

把 `CREDENTIALS_FIELDS` 数组长度从 5 改为 6，并加入：

```rust
("security_key", SensitivityLevel::Secret),
```

- [ ] **Step 5: 实现 RedactedDebug**

```rust
pub struct RedactedDebug<'a, T: ?Sized> {
    value: &'a T,
}

impl<T: ?Sized> RedactedDebug<'_, T> {
    #[inline]
    pub const fn new(value: &T) -> RedactedDebug<'_, T> {
        RedactedDebug { value }
    }
}

impl<T: ?Sized> std::fmt::Debug for RedactedDebug<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = self.value;
        formatter.write_str("<redacted>")
    }
}

#[inline]
pub const fn redacted_debug<T: ?Sized>(value: &T) -> RedactedDebug<'_, T> {
    RedactedDebug::new(value)
}
```

补全 core/root reexport 和 `tests/lib_tests.rs`。

- [ ] **Step 6: 运行相关测试并确认 GREEN**

```bash
cargo test --locked --features web --test adapter_tests url_sanitizer
cargo test --locked --test core_tests sensitive_field_preset
cargo test --locked --test core_tests redacted_debug
```

Expected: 三组测试 PASS。

### Task 6: multipart 重复 header/参数 fail closed

**Files:**
- Create: `rs-sanitize/src/adapter/http/internal/mod.rs`
- Create: `rs-sanitize/src/adapter/http/internal/header_parameter.rs`
- Modify: `rs-sanitize/src/adapter/http/content_type.rs`
- Modify: `rs-sanitize/src/adapter/http/multipart.rs`
- Modify: `rs-sanitize/tests/adapter/http/http_body_sanitizer_tests.rs`

**Interfaces:**
- Produces: private `HeaderParameter::{Absent, Value, Invalid}`
- Produces: duplicate Content-Disposition/Content-Type/name/filename/filename* 整体 redaction

- [ ] **Step 1: 写重复 header 和参数失败测试**

```rust
#[test]
fn test_http_body_sanitizer_redacts_duplicate_multipart_headers() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static(
        "multipart/form-data; boundary=boundary",
    );
    for body in [
        "--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Disposition: form-data; name=password\r\n\r\nsecret\r\n--boundary--\r\n",
        "--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\nContent-Type: application/json\r\n\r\nsecret\r\n--boundary--\r\n",
    ] {
        let result = sanitizer.sanitize_body(
            body.as_bytes(),
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );
        assert_eq!(result.to_string(), "<redacted: multipart body>");
    }
}

#[test]
fn test_http_body_sanitizer_redacts_duplicate_multipart_parameters() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static(
        "multipart/form-data; boundary=boundary",
    );
    let body = "--boundary\r\nContent-Disposition: form-data; name=note; name=password\r\n\r\nsecret\r\n--boundary--\r\n";

    let result = sanitizer.sanitize_body(
        body.as_bytes(),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(result.to_string(), "<redacted: multipart body>");
}
```

- [ ] **Step 2: 运行测试并确认 RED**

```bash
cargo test --locked --features http --test adapter_tests duplicate_multipart
```

Expected: 至少一个 case 被当前 last-header/first-parameter 逻辑接受。

- [ ] **Step 3: 实现 header parameter 状态 parser**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HeaderParameter {
    Absent,
    Value(String),
    Invalid,
}
```

`parse(value, name)` 遍历 respecting-quotes 的全部 segment：第一次匹配保存 decoded
value；第二次同名匹配立即返回 `Invalid`；malformed quote/escape/CR/LF 返回
`Invalid`；未匹配返回 `Absent`。保留现有 quoted semicolon 和 backslash escape 行为。

- [ ] **Step 4: 接入 Content-Type 与 multipart part parser**

`multipart_boundary` 只接受 `HeaderParameter::Value`。multipart part header 循环改为：

```rust
if header_name.eq_ignore_ascii_case("content-disposition") {
    if content_disposition.replace(header_value).is_some() {
        return None;
    }
} else if header_name.eq_ignore_ascii_case("content-type")
    && content_type.replace(header_value).is_some()
{
    return None;
}
```

`name`、`filename`、`filename*` 出现 `Invalid` 时返回 `None`；`Absent` 保留现有
unnamed/non-file 安全路径。

- [ ] **Step 5: 运行 multipart 与完整 HTTP tests 并确认 GREEN**

```bash
cargo test --locked --features http --test adapter_tests duplicate_multipart
cargo test --locked --features http --test adapter_tests http_body_sanitizer
```

Expected: 新回归与既有 quoted/boundary/malformed tests 全部 PASS。

### Task 7: 内部文件、测试文件名和 inline 收口

**Files:**
- Move: `rs-sanitize/src/adapter/http/body_input_kind.rs` → `rs-sanitize/src/adapter/http/internal/body_input_kind.rs`
- Split from: `rs-sanitize/src/adapter/http/multipart.rs`
- Create: `rs-sanitize/src/adapter/http/internal/multipart_delimiter.rs`
- Modify: `rs-sanitize/src/adapter/http/internal/mod.rs`
- Modify: `rs-sanitize/src/adapter/http/mod.rs`
- Move four adapter test files
- Modify: `rs-sanitize/tests/adapter/mod.rs`
- Modify: trivial accessor files under `rs-sanitize/src/core/` and `rs-sanitize/src/adapter/`

**Interfaces:**
- Preserves: all public paths and runtime behavior
- Produces: private types each in `http/internal/` own file; test basenames aligned

- [ ] **Step 1: 移动 private types**

执行已批准的文件移动：

```bash
mv src/adapter/http/body_input_kind.rs src/adapter/http/internal/body_input_kind.rs
```

把 `MultipartDelimiter` 的完整 enum 与 impl 移入
`internal/multipart_delimiter.rs`。`internal/mod.rs` 使用：

```rust
pub(super) mod body_input_kind;
pub(super) mod header_parameter;
pub(super) mod multipart_delimiter;
```

更新 imports；`http/mod.rs` 删除旧 `mod body_input_kind;`，增加 `mod internal;`。

- [ ] **Step 2: 重命名四个测试文件**

```bash
mv tests/adapter/argv_tests.rs tests/adapter/argv_sanitizer_tests.rs
mv tests/adapter/env_tests.rs tests/adapter/env_sanitizer_tests.rs
mv tests/adapter/form_urlencoded_tests.rs tests/adapter/form_url_encoded_sanitizer_tests.rs
mv tests/adapter/url_tests.rs tests/adapter/url_sanitizer_tests.rs
```

`tests/adapter/mod.rs` 改为对应 module names，并保留原 feature gates。

- [ ] **Step 3: 只给 trivial methods 增加 inline**

限定在以下类别：

```text
new/empty constructors that only build fields
immutable/mutable field_sanitizer and policy accessors
BodySanitization metadata accessors
MaskPolicies level accessors/setters
thin sanitize_value forwarding methods
SensitiveFieldPreset::fields
```

不得给 JSON、NDJSON、multipart、URL serialization、argv parsing、map iteration 等
包含循环/解析/分配的函数增加 inline。

- [ ] **Step 4: 格式化并验证组织调整**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo test --locked --no-default-features
cargo test --locked --all-features
```

Expected: 格式、core-only 和 all-feature tests PASS；公共 import path 不变。

### Task 8: 私有化 rs-http LogSanitizePolicy

**Files:**
- Modify: `rs-http/src/sanitize/log_sanitize_policy.rs`
- Modify: `rs-http/src/sanitize/log_sanitizer.rs`
- Modify: `rs-http/src/options/http_client_options.rs`
- Modify: `rs-http/src/lib.rs`
- Modify: all rs-http source/tests/docs found by field-name search
- Test: `rs-http/tests/sanitize/log_sanitize_policy_tests.rs`
- Test: `rs-http/tests/options/http_client_options_tests.rs`

**Interfaces:**
- Consumes: Task 2 private policy APIs
- Produces: domain methods for header/query/body, crate-root `SensitivityLevel` reexport

- [ ] **Step 1: 先把 policy tests 改成目标 public API**

```rust
use qubit_http::{LogSanitizePolicy, SensitivityLevel};

#[test]
fn test_log_sanitize_policy_default_contains_common_sensitive_names() {
    let policy = LogSanitizePolicy::default();
    assert_eq!(
        policy.sensitivity_for_header("Authorization"),
        Some(SensitivityLevel::High),
    );
    assert_eq!(
        policy.sensitivity_for_query_param("access_token"),
        Some(SensitivityLevel::High),
    );
    assert_eq!(
        policy.sensitivity_for_body_field("password"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_log_sanitize_policy_add_is_strongest_and_set_is_explicit() {
    let mut policy = LogSanitizePolicy::default();
    policy.insert_sensitive_body_field("password", SensitivityLevel::Low);
    assert_eq!(
        policy.sensitivity_for_body_field("password"),
        Some(SensitivityLevel::Secret),
    );
    policy.set_sensitive_body_field_level("password", SensitivityLevel::Low);
    assert_eq!(
        policy.sensitivity_for_body_field("password"),
        Some(SensitivityLevel::Low),
    );
}
```

- [ ] **Step 2: 运行并确认 RED**

```bash
cargo test --locked --test mod log_sanitize_policy
```

Expected: 新领域方法和 root reexport 尚不存在。

- [ ] **Step 3: 实现 LogSanitizePolicy facade**

字段设为 private。`default` 建三个 `SensitiveFields::default()`；`empty` 建三个
`SensitiveFields::new()`。header/query/body 三个 domain 的 insert/extend/set/remove/query
public 方法按设计规格实现：

```rust
pub fn insert_sensitive_header(&mut self, name: &str, level: SensitivityLevel) {
    self.sensitive_headers.insert_strongest(name, level);
}

pub fn set_sensitive_header_level(
    &mut self,
    name: &str,
    level: SensitivityLevel,
) {
    self.sensitive_headers.insert(name, level);
}

pub fn remove_sensitive_header(
    &mut self,
    name: &str,
) -> Option<SensitivityLevel> {
    self.sensitive_headers.remove(name)
}

pub fn sensitivity_for_header(&self, name: &str) -> Option<SensitivityLevel> {
    self.sensitive_headers.level_for(name)
}
```

query/body 和 extend 方法使用同一语义但各自访问对应集合。增加三个
`pub(crate)` 只读 accessor 供 `LogSanitizer` 使用。

在 `rs-http/src/lib.rs` 增加：

```rust
pub use qubit_sanitize::SensitivityLevel;
```

- [ ] **Step 4: 迁移所有直接字段访问**

生产代码：

```rust
policy.sensitive_headers()
policy.sensitive_query_params()
policy.sensitive_body_fields()
```

配置追加改为对应 `extend_sensitive_*`；测试构造 custom-only policy 使用
`LogSanitizePolicy::empty()` 与 `insert_sensitive_*`。`field_sanitizer` helper 使用：

```rust
FieldSanitizer::new(FieldSanitizePolicy::new(
    fields.clone(),
    MaskPolicies::default(),
))
```

README 与中英文用户指南示例改用 public facade，不再 import `SensitiveFields`。

- [ ] **Step 5: 确认无外部字段访问并运行 GREEN**

```bash
rg -n '\.(sensitive_headers|sensitive_query_params|sensitive_body_fields)' src tests README.md README.zh_CN.md doc
cargo test --locked --test mod log_sanitize_policy
cargo test --locked --test mod http_client_options
cargo test --locked --test mod log_sanitizer
```

Expected: `rg` 只剩内部 accessor 实现或配置 input 字段；相关 tests PASS。

### Task 9: rs-http 消费结构化 body metadata

**Files:**
- Modify: `rs-http/src/sanitize/log_sanitizer.rs`
- Modify: `rs-http/tests/sanitize/log_sanitizer_tests.rs`
- Modify: `rs-http/doc/user_guide.en.md`
- Modify: `rs-http/doc/user_guide.zh_CN.md`

**Interfaces:**
- Consumes: Task 4 的 `BodySanitization`
- Preserves: `rs-http` 显式启用 body 日志时的 text pass-through 契约
- Removes: `normalize_error_truncation_suffix` 与 counted marker parsing

- [ ] **Step 1: 用既有失败测试锁定 text 日志契约**

基线已稳定复现以下测试失败，实际值为 `<redacted: text body>`，而既有契约要求记录
已显式启用的 text body：

```bash
cargo test --locked --test mod client::http_logger_policy_tests::test_log_request_text_body -- --exact
cargo test --locked --test mod sanitize::log_sanitizer_tests::test_log_sanitizer_sanitize_body_preview_keeps_multipart_text_part -- --exact
```

在 `LogSanitizer::new` 构造 `HttpBodySanitizer` 时显式设置
`TextBodyPolicy::PassThrough`。`HttpBodySanitizer::default()` 的通用安全默认仍为
`Redact`。

- [ ] **Step 2: 确认既有 text/multipart 日志回归恢复 GREEN**

```bash
cargo test --locked --test mod client::http_logger_policy_tests::test_log_request_text_body -- --exact
cargo test --locked --test mod sanitize::log_sanitizer_tests::test_log_sanitizer_sanitize_body_preview_keeps_multipart_text_part -- --exact
```

- [ ] **Step 3: 保留并强化含 marker 正文的回归测试**

使用既有 `test_log_sanitizer_error_response_truncation_normalizes_suffix_only`，追加断言
输出只有一个末尾 `...<truncated>`，正文中的
`...<truncated 2 bytes>` 保持原样。

- [ ] **Step 4: 在尚未迁移的 rs-http 上确认 RED**

Task 4 改变了返回类型，此时运行：

```bash
cargo test --locked --test mod error_response_truncation_normalizes_suffix_only
```

Expected: `LogSanitizer` 仍把 `BodySanitization` 当作 `String`，编译失败。

- [ ] **Step 5: 用 metadata 渲染 context-specific suffix**

```rust
let result = self.body_sanitizer.sanitize_body_preview(
    preview.prefix(),
    preview.source_len(),
    content_type.as_ref(),
    LOG_NAME_MATCH_MODE,
);
if preview.context == BodyLogContext::ErrorResponse && result.is_truncated() {
    format!("{}{}", result.into_content(), preview.truncation_suffix())
} else {
    result.into_rendered()
}
```

删除 `normalize_error_truncation_suffix` 及其精确 marker 构造代码。invalid local
Content-Type 的 rs-http marker 路径保持现状。

- [ ] **Step 6: 验证不再解析 marker**

```bash
rg -n 'strip_suffix|truncated \{\} bytes|normalize_error_truncation_suffix' src/sanitize tests/sanitize
cargo test --locked --test mod log_sanitizer
cargo test --locked --test mod http_error
```

Expected: `rg` 无旧 parser；测试 PASS，历史 error-response suffix 保持。

### Task 10: rs-command 安全 Debug 与 0.5.0 版本

**Files:**
- Modify: `rs-command/src/command_output.rs`
- Modify: `rs-command/tests/command_output_tests.rs`
- Modify: `rs-command/tests/command_error_tests.rs`
- Modify: `rs-command/Cargo.toml`
- Modify: `rs-command/Cargo.lock`
- Modify: `rs-command/README.md`
- Modify: `rs-command/README.zh_CN.md`

**Interfaces:**
- Consumes: Task 5 的 `redacted_debug`
- Produces: `CommandOutput::Debug` 不输出 stdout/stderr bytes
- Produces: `qubit-command 0.5.0`

- [ ] **Step 1: 写 CommandOutput 和 CommandError no-leak 失败测试**

在非 Windows command output tests 中增加：

```rust
#[test]
fn test_command_output_debug_redacts_captured_streams() {
    let output = CommandRunner::new()
        .run(Command::shell(
            "printf stdout-secret; printf stderr-secret >&2",
        ))
        .expect("command should run successfully");

    let debug = format!("{output:?}");
    let stdout_debug = format!("{:?}", b"stdout-secret".to_vec());
    let stderr_debug = format!("{:?}", b"stderr-secret".to_vec());
    assert!(!debug.contains("stdout-secret"));
    assert!(!debug.contains("stderr-secret"));
    assert!(!debug.contains(&stdout_debug));
    assert!(!debug.contains(&stderr_debug));
    assert!(debug.contains("stdout_len"));
    assert!(debug.contains("stderr_len"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn test_command_error_debug_does_not_expose_captured_streams() {
    let error = CommandRunner::new()
        .run(Command::shell(
            "printf stdout-secret; printf stderr-secret >&2; exit 7",
        ))
        .expect_err("command should fail");

    let debug = format!("{error:?}");
    let stdout_debug = format!("{:?}", b"stdout-secret".to_vec());
    let stderr_debug = format!("{:?}", b"stderr-secret".to_vec());
    assert!(!debug.contains("stdout-secret"));
    assert!(!debug.contains("stderr-secret"));
    assert!(!debug.contains(&stdout_debug));
    assert!(!debug.contains(&stderr_debug));
}
```

- [ ] **Step 2: 运行并确认 RED**

```bash
cargo test --locked --test command_output_tests debug_redacts
cargo test --locked --test command_error_tests captured_streams
```

Expected: 当前派生 Debug 包含原始 byte arrays/文本值，断言失败。

- [ ] **Step 3: 手写 CommandOutput::Debug**

移除 `Debug` derive，增加：

```rust
use std::fmt;
use qubit_sanitize::redacted_debug;

impl fmt::Debug for CommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandOutput")
            .field("status", &self.status)
            .field("stdout", &redacted_debug(&self.stdout))
            .field("stdout_len", &self.stdout.len())
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr", &redacted_debug(&self.stderr))
            .field("stderr_len", &self.stderr.len())
            .field("stderr_truncated", &self.stderr_truncated)
            .field("elapsed", &self.elapsed)
            .finish()
    }
}
```

原始 bytes accessors 不变。

- [ ] **Step 4: 确认 GREEN**

```bash
cargo test --locked --test command_output_tests
cargo test --locked --test command_error_tests
```

Expected: no-leak 与既有行为测试 PASS。

- [ ] **Step 5: 升级版本并更新锁文件**

`Cargo.toml` package version 改为 `0.5.0`。运行：

```bash
cargo check
cargo test --locked
```

Expected: `Cargo.lock` 的本地 package 为 `qubit-command 0.5.0`，完整测试 PASS。

### Task 11: 同步 rs-mime 与 rs-magika 依赖图

**Files:**
- Modify: `rs-value/Cargo.toml`
- Modify: `rs-value/Cargo.lock`
- Verify: `rs-config/Cargo.toml`
- Modify if re-resolved: `rs-config/Cargo.lock`
- Modify: `rs-mime/Cargo.toml`
- Modify: `rs-mime/Cargo.lock`
- Modify: `rs-mime/README.md`
- Modify: `rs-mime/README.zh_CN.md`
- Modify: `rs-magika/Cargo.lock`

**Interfaces:**
- Produces: `rs-value -> local qubit-datatype 0.6.0`
- Verifies: `rs-config` 依赖图只有一个 `qubit-datatype` package identity
- Consumes: `qubit-command 0.5.0` → `qubit-sanitize 0.3.0`
- Produces: 锁文件中不再包含 `qubit-sanitize 0.2.2`

- [ ] **Step 1: 修复 rs-value 的本地 datatype identity**

将：

```toml
qubit-datatype = { version = "0.6", default-features = false }
```

改为：

```toml
qubit-datatype = {
    path = "../rs-datatype",
    version = "0.6",
    default-features = false,
}
```

这是 manifest/lock 修复，用已经复现的下游编译错误作为 RED。运行：

```bash
cargo check --locked
cargo check
cargo test --locked
```

Expected: 第一条因 lock source 改变而失败；更新后 rs-value tests PASS。

- [ ] **Step 2: 验证 rs-config 的类型身份唯一**

```bash
cargo tree --locked -d
cargo test --locked
```

Expected: 不出现两份 `qubit-datatype 0.6.0`，tests PASS；若 Cargo 因 rs-value
manifest identity 更新而调整 lock，只接受该机械更新。

- [ ] **Step 3: 修改 rs-mime manifest**

```toml
[package]
version = "0.9.1"

[dependencies]
qubit-command = { version = "0.5", path = "../rs-command" }
```

README 依赖示例保持兼容范围 `qubit-mime = "0.9"`，发布说明文字如出现精确
`0.9.0` 则改为 `0.9.1`。

- [ ] **Step 4: 用 locked check 证明旧锁不匹配**

```bash
cargo check --locked
```

Expected: Cargo 报告 lock file 需要更新，或旧 registry command 无法满足新的 path
dependency identity。

- [ ] **Step 5: 由 Cargo 生成 rs-mime lock 更新**

```bash
cargo check
cargo test --locked
```

Expected: tests PASS；lock 中包含 path `qubit-command 0.5.0`、path
`qubit-sanitize 0.3.0`。

- [ ] **Step 6: 更新 rs-magika transitive lock**

Run from `rs-magika`:

```bash
cargo check
cargo test --locked --no-default-features
```

Expected: lock 更新到本地 `qubit-mime 0.9.1`、`qubit-command 0.5.0`、
`qubit-sanitize 0.3.0`；不触发 bundled ONNX runtime 下载。

- [ ] **Step 7: 验证旧依赖完全消失且 datatype identity 唯一**

```bash
rg -n 'name = "qubit-(mime|command|sanitize)"|version = "0\.(9\.1|5\.0|3\.0|2\.2|4\.2)"' \
  /home/starfish/working/qubit/rust-common/rs-mime/Cargo.lock \
  /home/starfish/working/qubit/rust-common/rs-magika/Cargo.lock
```

Expected: 目标 packages 只出现 0.9.1/0.5.0/0.3.0，不出现 sanitizer 0.2.2 或
command 0.4.2；`cargo tree --locked -d` 不再报告两份 `qubit-datatype 0.6.0`。

### Task 12: 文档迁移与分层最终验证

**Files:**
- Modify: `rs-sanitize/README.md`
- Modify: `rs-sanitize/README.zh_CN.md`
- Modify: `rs-sanitize/src/lib.rs`
- Modify: `rs-http/README.md`
- Modify: `rs-http/README.zh_CN.md`
- Modify: `rs-http/doc/user_guide.en.md`
- Modify: `rs-http/doc/user_guide.zh_CN.md`
- Verify: `rs-value` and `rs-config` changes from Task 11
- Verify: all files changed by Tasks 1–11

**Interfaces:**
- Documents: 结构化 body result、private policy facade、strongest/set 差异、URL path
  边界、Debug redaction、版本和 feature matrix
- Verifies: all acceptance criteria in the design spec

- [ ] **Step 1: 更新 rs-sanitize 文档示例**

body 示例使用：

```rust
let result = sanitizer.sanitize_body_preview(
    prefix,
    source_len,
    content_type.as_ref(),
    NameMatchMode::ExactOrSuffix,
);
println!("{result}");
assert_eq!(result.truncated_bytes(), source_len - prefix.len());
```

policy 示例使用 constructors/accessors；文档明确 `insert` 可覆盖降级、add facade
使用 strongest、`set_sensitive_field_level` 才显式覆盖。保留 `# Parameters`。

- [ ] **Step 2: 更新 rs-http 文档示例**

```rust
use qubit_http::{LogSanitizePolicy, SensitivityLevel};

let mut policy = LogSanitizePolicy::default();
policy.insert_sensitive_header("x-tenant-secret", SensitivityLevel::Secret);
policy.insert_sensitive_query_param("tenant_token", SensitivityLevel::High);
policy.insert_sensitive_body_field("customer_secret", SensitivityLevel::Secret);
```

删除要求用户直接 import `qubit_sanitize::SensitiveFields` 的示例。

- [ ] **Step 3: 运行静态契约搜索**

```bash
rg -n 'features? = \["core"\]' rs-sanitize
rg -n 'normalize_error_truncation_suffix|strip_suffix\(&counted\)' rs-http/src rs-http/tests
rg -n 'FieldSanitizePolicy \{|MaskPolicies \{' rs-sanitize rs-http
rg -n 'sensitive_(headers|query_params|body_fields)\s*:' rs-http/src rs-http/tests
rg -n '# Arguments' rs-sanitize/src
```

Expected: 前四项无遗留不合规调用；最后一项无输出，继续使用 `# Parameters`。

- [ ] **Step 4: 运行 rs-sanitize 完整验证**

```bash
cd /home/starfish/working/qubit/rust-common/rs-sanitize
./align-ci.sh
./ci-check.sh
# 仅当 ci-check.sh 报告 coverage 低于阈值时运行：
./coverage.sh json
```

Expected: 全部 exit 0；feature matrix 覆盖 core/web/http/all。

- [ ] **Step 5: 运行 rs-command 与 rs-http 完整验证**

```bash
cd /home/starfish/working/qubit/rust-common/rs-command
./align-ci.sh
./ci-check.sh
# 仅当 ci-check.sh 报告 coverage 低于阈值时运行：
./coverage.sh json

cd /home/starfish/working/qubit/rust-common/rs-http
./align-ci.sh
./ci-check.sh
# 仅当 ci-check.sh 报告 coverage 低于阈值时运行：
./coverage.sh json
```

Expected: 两个仓库全部 exit 0，无新 warning。

- [ ] **Step 6: 运行 rs-mime 与 rs-magika 验证**

```bash
cd /home/starfish/working/qubit/rust-common/rs-mime
cargo fmt --all -- --check
./ci-check.sh

cd /home/starfish/working/qubit/rust-common/rs-magika
cargo fmt --all -- --check
cargo test --locked --no-default-features
```

Expected: exit 0；依赖图保持 0.9.1 → 0.5.0 → 0.3.0。

- [ ] **Step 7: 运行 rs-value 与 rs-config 验证**

```bash
cd /home/starfish/working/qubit/rust-common/rs-value
./align-ci.sh
./ci-check.sh

cd /home/starfish/working/qubit/rust-common/rs-config
./align-ci.sh
./ci-check.sh
```

仅在相应 CI 报告 coverage 低于阈值时运行 `./coverage.sh json`。

- [ ] **Step 8: 分仓库审查最终 diff**

对 `rs-sanitize`、`rs-http`、`rs-command`、`rs-value`、`rs-config`、`rs-mime`、
`rs-magika` 分别运行：

```bash
git status --short
git --no-pager diff --stat
git --no-pager diff --check
```

Expected: 只包含本计划授权范围；不包含 `rs-platform`、`rs-llmsdk-core` 或用户既有
修改；无 whitespace error。不得执行 add/commit/push。

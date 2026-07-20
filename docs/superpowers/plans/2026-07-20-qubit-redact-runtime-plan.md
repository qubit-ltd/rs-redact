# qubit-redact Runtime、HTTP 与下游迁移实施计划

> **面向智能体执行者：** 必须使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans，逐项实施本计划。各步骤使用复选框（`- [ ]`）语法跟踪进度。

**目标：** 将未发布的 `qubit-sanitize` 破坏性重构为 `qubit-redact`，完成不可变策略、全局默认、类型化文本、argv/env、可选 HTTP 有界预览，并同步迁移 `rs-http`、`rs-command`、`rs-config`。

**架构：** 先在主 crate 中以测试驱动建立新 policy 与 redactor API，再把现有格式解析实现迁移到新门面，最后删除全部旧 API 并迁移三个下游。HTTP parser 的成熟算法保留，但只能通过 `HttpRedactor`、受检 `BodyCapture` 和双重预算访问。

**技术栈：** Rust 1.94、edition 2024（`rs-http` 保持自身 edition 2021）、标准库 `Arc`/`OnceLock`、`http`、`url`、`form_urlencoded`、`serde_json`、`proptest`、Cargo feature matrix。

**临时工作区：** `/tmp/superpowers-qubit-redact-design.FAibmX`

**Temporary Workspace:** `/tmp/superpowers-qubit-redact-design.FAibmX`

**临时工作区清理：** 执行期间必须保留该工作区，直至任务成功完成。成功后，仅在完成相同的路径组件验证后才能删除；不得使用字符串前缀判断包含关系。必须确认：解析后的工作区不是解析后的临时根目录；其解析后的父目录与临时根目录完全相同；其目录名以 `superpowers-` 开头；`.superpowers-session` 是空的、非符号链接的普通文件。如果执行时存在当前仓库，还必须证明工作区与仓库完全双向不重叠：任一路径都不等于另一路径，也不包含另一路径。否则，应记录未检测到当前仓库，并继续完成其余验证。

## 全局约束

- 设计规范：`/tmp/superpowers-qubit-redact-design.FAibmX/2026-07-20-qubit-redact-redesign-design.md`。
- 修改四个独立 Git 仓库：`rs-sanitize`、`rs-http`、`rs-command`、`rs-config`；每个仓库单独检查和验证。
- 执行前使用 `using-git-worktrees` 检测现有隔离；若用户同意创建 worktree，则每个仓库独立创建。
- 不保留旧 package、crate、type alias、deprecated API 或 feature alias。
- 主 crate package 为 `qubit-redact 0.1.0`，lib crate 为 `qubit_redact`；本地目录本轮仍叫 `rs-sanitize`。
- 主 crate `default = []`，仅保留可选 `http` feature；领域对象 `derive`/`serde` 留给第二份计划。
- 所有 public struct、enum、trait 单独文件；生产代码禁止 `unwrap`、`expect`、`panic!`、`unreachable!` 和 `unsafe`。
- 所有新增或改变行为遵循 RED→GREEN→REFACTOR；必须记录每次 RED 的预期失败原因。
- 不运行 `git add`、`git commit` 或 `git push`，除非用户另行明确授权。下文提交步骤仅在获得授权后执行；未授权时记录“跳过提交”并继续。
- 不修改 GitHub 仓库名；Cargo metadata 在仓库改名前继续指向当前有效 `rs-sanitize` URL。

---

### Task 1：切换 package/crate 身份

**文件：**
- 新建：`rs-sanitize/tests/crate_name_tests.rs`
- 修改：`rs-sanitize/Cargo.toml`
- 修改：`rs-sanitize/Cargo.lock`
- 修改：`rs-sanitize/fuzz/Cargo.toml`
- 修改：`rs-sanitize/fuzz/Cargo.lock`（若存在）
- 修改：`rs-sanitize/tests/**/*.rs`、`rs-sanitize/fuzz/fuzz_targets/*.rs` 中的 crate import

**接口：**
- 输入依赖：现有 `qubit_sanitize` lib。
- 输出接口：package `qubit-redact 0.1.0`、lib `qubit_redact`；旧公共 Rust 类型暂时仍存在，供后续任务逐项替换。

- [ ] **步骤 1：编写 crate 名失败测试**

```rust
// tests/crate_name_tests.rs
use qubit_redact as redact;

#[test]
fn test_crate_is_named_qubit_redact() {
    let _ = core::any::type_name::<redact::FieldSanitizer>();
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test crate_name_tests --no-default-features`

预期：编译失败，提示无法解析 crate `qubit_redact`。

- [ ] **步骤 3：修改 manifest 和仓库内 import**

在 `Cargo.toml` 使用：

```toml
[package]
name = "qubit-redact"
version = "0.1.0"
edition = "2024"
rust-version = "1.94"

[lib]
name = "qubit_redact"
doctest = true
```

保留当前 repository/homepage URL；documentation 改为 `https://docs.rs/qubit-redact`，
description 改为 “Rule-driven redaction for fields, diagnostics, HTTP data, and Rust domain objects”。
使用 `apply_patch` 把主仓库测试、doctest 和 fuzz target 中的 `qubit_sanitize` 改为
`qubit_redact`。fuzz dependency 改为：

```toml
qubit-redact = { path = "..", default-features = false, features = ["http"] }
```

- [ ] **步骤 4：运行测试并确认 GREEN**

运行：

```text
cargo test --test crate_name_tests --no-default-features
cargo test --no-default-features
cargo check --manifest-path fuzz/Cargo.toml
```

预期：crate 名测试及现有 core/argv/env 测试通过，fuzz package 可解析新依赖名。

- [ ] **步骤 5：条件提交**

若用户已授权：

```bash
git add Cargo.toml Cargo.lock tests fuzz
git commit -m "refactor(包名)!: 重命名为 qubit-redact"
```

否则记录“未获授权，跳过提交”。

---

### Task 2：建立新 policy 基础类型与遮盖模型

**文件：**
- 新建：`rs-sanitize/src/policy/mod.rs`
- 新建：`rs-sanitize/src/policy/sensitivity.rs`
- 新建：`rs-sanitize/src/policy/field_name_matching.rs`
- 新建：`rs-sanitize/src/policy/mask_policy.rs`
- 新建：`rs-sanitize/src/policy/masking_policy.rs`
- 新建：`rs-sanitize/src/policy/sensitive_field_preset.rs`
- 新建：`rs-sanitize/src/policy/internal/mod.rs`
- 新建：`rs-sanitize/src/policy/internal/field_name.rs`
- 新建：`rs-sanitize/tests/policy_tests.rs`
- 新建：`rs-sanitize/tests/policy/mod.rs`
- 新建：`rs-sanitize/tests/policy/masking_policy_tests.rs`
- 修改：`rs-sanitize/src/lib.rs`

**接口：**
- 输入依赖：现有 canonicalization、`MaskPolicy`、`MaskPolicies`、preset 字段表。
- 输出接口：`Sensitivity`、`FieldNameMatching`、`MaskPolicy`、`MaskingPolicy`、
  `SensitiveFieldPreset`、内部 `canonicalize_field_name` 和 token suffix iterator。

- [ ] **步骤 1：编写新类型失败测试**

```rust
// tests/policy/masking_policy_tests.rs
use qubit_redact::{
    FieldNameMatching,
    MaskPolicy,
    MaskingPolicy,
    Sensitivity,
};

#[test]
fn test_default_masking_policy_preserves_existing_semantics() {
    let policy = MaskingPolicy::default();

    assert_eq!(policy.mask(Sensitivity::Low, "abcdefgh"), "ab****gh");
    assert_eq!(policy.mask(Sensitivity::Medium, "abcdefgh"), "*******h");
    assert_eq!(policy.mask(Sensitivity::High, "abcdefgh"), "****");
    assert_eq!(policy.mask(Sensitivity::Secret, "abcdefgh"), "<redacted>");
    assert_eq!(policy.mask(Sensitivity::Secret, ""), "");
}

#[test]
fn test_field_name_matching_names_are_explicit() {
    assert_ne!(FieldNameMatching::Exact, FieldNameMatching::ExactOrTokenSuffix);
    assert_eq!(MaskPolicy::fixed("x").mask("secret"), "x");
}
```

在 `tests/policy_tests.rs` 写入 `mod policy;`，在 `tests/policy/mod.rs` 注册
`masking_policy_tests`。

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test policy_tests --no-default-features`

预期：编译失败，提示新类型尚未导出。

- [ ] **步骤 3：实现新基础类型**

核心签名固定为：

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Secret,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldNameMatching {
    Exact,
    ExactOrTokenSuffix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskingPolicy {
    low: MaskPolicy,
    medium: MaskPolicy,
    high: MaskPolicy,
    secret: MaskPolicy,
}

impl MaskingPolicy {
    #[must_use]
    pub fn mask<'a>(
        &self,
        level: Sensitivity,
        value: &'a str,
    ) -> Cow<'a, str> {
        self.for_level(level).mask(value)
    }

    #[must_use]
    pub const fn for_level(&self, level: Sensitivity) -> &MaskPolicy {
        match level {
            Sensitivity::Low => &self.low,
            Sensitivity::Medium => &self.medium,
            Sensitivity::High => &self.high,
            Sensitivity::Secret => &self.secret,
        }
    }
}
```

迁移现有 Unicode scalar 遮盖算法及所有 preset 字段，不改变输出。模块只导出新名称；
旧模块暂留到任务 9 删除。

- [ ] **步骤 4：运行测试并确认 GREEN**

运行：`cargo test --test policy_tests --no-default-features`

预期：全部通过。

- [ ] **步骤 5：迁移原有算法测试并重跑**

将现有 `mask_policy_tests.rs`、`mask_policies_tests.rs`、`field_name_tests.rs` 和
`sensitive_field_preset_tests.rs` 的断言复制到新 test module，import 改为新类型。

运行：`cargo test --test policy_tests --no-default-features`

预期：ASCII、Unicode、空字符串、preset 和 canonicalization 测试全部通过。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/policy src/lib.rs tests/policy tests/policy_tests.rs
git commit -m "refactor(策略)!: 建立新的遮盖基础类型"
```

---

### Task 3：实现不可变 RedactionPolicy、builder 与匹配优先级

**文件：**
- 新建：`rs-sanitize/src/policy/redaction_policy.rs`
- 新建：`rs-sanitize/src/policy/redaction_policy_builder.rs`
- 新建：`rs-sanitize/src/policy/policy_error.rs`
- 新建：`rs-sanitize/src/policy/sensitive_field_rule.rs`
- 新建：`rs-sanitize/src/policy/allow_rule.rs`
- 新建：`rs-sanitize/tests/policy/redaction_policy_tests.rs`
- 修改：`rs-sanitize/src/policy/mod.rs`
- 修改：`rs-sanitize/tests/policy/mod.rs`

**接口：**
- 输入依赖：任务 2 的字段规范化、preset、`Sensitivity`、`MaskingPolicy`。
- 输出接口：`RedactionPolicy::standard/default/builder/empty_builder/builder_from`、
  `RedactionPolicyBuilder::{matching,include_preset,raise,override_level,allow_exact,allow_suffix,mask,build}`、
  `RedactionPolicy::sensitivity_for`。

- [ ] **步骤 1：编写规则优先级失败测试**

```rust
use qubit_redact::{
    FieldNameMatching,
    RedactionPolicy,
    Sensitivity,
};

#[test]
fn test_exact_allow_does_not_allow_contextual_suffix() {
    let policy = RedactionPolicy::builder()
        .allow_exact("access_token")
        .build()
        .unwrap();

    assert_eq!(policy.sensitivity_for("access_token"), None);
    assert_eq!(
        policy.sensitivity_for("OPENAI_ACCESS_TOKEN"),
        Some(Sensitivity::High),
    );
}

#[test]
fn test_suffix_allow_is_explicitly_broad() {
    let policy = RedactionPolicy::builder()
        .allow_suffix("access_token")
        .build()
        .unwrap();

    assert_eq!(policy.sensitivity_for("access_token"), None);
    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), None);
}

#[test]
fn test_longest_rule_wins_before_shorter_token() {
    let policy = RedactionPolicy::builder()
        .override_level("token", Sensitivity::Secret)
        .override_level("access_token", Sensitivity::Medium)
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .build()
        .unwrap();

    assert_eq!(
        policy.sensitivity_for("OPENAI_ACCESS_TOKEN"),
        Some(Sensitivity::Medium),
    );
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test policy_tests redaction_policy --no-default-features`

预期：编译失败，提示 `RedactionPolicy` 尚不存在。

- [ ] **步骤 3：实现不可变存储与 builder**

使用以下不可变布局：

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    inner: Arc<RedactionPolicyInner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RedactionPolicyInner {
    sensitive: BTreeMap<String, Sensitivity>,
    allow_exact: BTreeSet<String>,
    allow_suffix: BTreeSet<String>,
    matching: FieldNameMatching,
    masking: MaskingPolicy,
}

#[derive(Debug, Clone)]
pub struct RedactionPolicyBuilder {
    sensitive: BTreeMap<String, Sensitivity>,
    allow_exact: BTreeSet<String>,
    allow_suffix: BTreeSet<String>,
    matching: FieldNameMatching,
    masking: MaskingPolicy,
    error: Option<PolicyError>,
}
```

`raise` 使用 `max(existing, requested)`；`override_level` 直接替换；allow 规则与敏感规则
允许并存。`build` 在存在空 canonical name 或空 fixed replacement 时返回
`PolicyError`。

匹配实现固定为：

```rust
pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
    let candidates = canonical_field_candidates(field, self.inner.matching);
    for (index, candidate) in candidates.enumerate() {
        let is_exact = index == 0;
        if (is_exact && self.inner.allow_exact.contains(&candidate))
            || self.inner.allow_suffix.contains(&candidate)
        {
            return None;
        }
        if let Some(level) = self.inner.sensitive.get(&candidate) {
            return Some(*level);
        }
    }
    None
}
```

`canonical_field_candidates` 必须复用现有 token-boundary 算法，并保证最长到最短、无重复。

- [ ] **步骤 4：运行测试并确认 GREEN**

运行：`cargo test --test policy_tests --no-default-features`

预期：规则优先级、preset 和 mask 测试全部通过。

- [ ] **步骤 5：增加 property test**

增加以下性质：

```rust
proptest! {
    #[test]
    fn prop_policy_lookup_is_deterministic(name in ".*") {
        let policy = RedactionPolicy::standard();
        prop_assert_eq!(
            policy.sensitivity_for(&name),
            policy.sensitivity_for(&name),
        );
    }
}
```

运行：`cargo test --test policy_tests --no-default-features`。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/policy tests/policy
git commit -m "feat(策略): 增加不可变字段脱敏策略"
```

---

### Task 4：实现一次性全局默认与快照语义

**文件：**
- 新建：`rs-sanitize/src/policy/global_default_already_set.rs`
- 新建：`rs-sanitize/tests/global_default_tests.rs`
- 修改：`rs-sanitize/src/policy/redaction_policy.rs`
- 修改：`rs-sanitize/src/policy/redaction_policy_builder.rs`
- 修改：`rs-sanitize/src/policy/mod.rs`
- 修改：`rs-sanitize/src/lib.rs`

**接口：**
- 输入依赖：任务 3 的不可变 `RedactionPolicy`。
- 输出接口：`RedactionPolicy::{standard,global_default,set_global_default}`、`Default`；
  `builder()` 从当前默认快照开始。

- [ ] **步骤 1：编写独立进程失败测试**

```rust
// tests/global_default_tests.rs
use qubit_redact::{
    GlobalDefaultAlreadySet,
    RedactionPolicy,
    Sensitivity,
};

#[test]
fn test_global_default_can_be_installed_once_and_is_snapshotted() {
    let before = RedactionPolicy::default();
    let custom = RedactionPolicy::empty_builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()
        .unwrap();

    RedactionPolicy::set_global_default(custom).unwrap();

    assert_eq!(
        RedactionPolicy::default().sensitivity_for("tenant_secret"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(before.sensitivity_for("tenant_secret"), None);
    assert_eq!(
        RedactionPolicy::set_global_default(RedactionPolicy::standard()),
        Err(GlobalDefaultAlreadySet),
    );
}
```

该 integration test 文件只能有这一个测试，保证 Cargo 用独立测试进程隔离一次性全局状态。

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test global_default_tests --no-default-features`

预期：编译失败，提示全局 API 尚不存在。

- [ ] **步骤 3：实现标准策略与 OnceLock**

```rust
static STANDARD_POLICY: LazyLock<RedactionPolicy> =
    LazyLock::new(RedactionPolicy::build_standard);
static GLOBAL_DEFAULT: OnceLock<Arc<RedactionPolicy>> = OnceLock::new();

impl RedactionPolicy {
    #[must_use]
    pub fn standard() -> Self {
        STANDARD_POLICY.clone()
    }

    #[must_use]
    pub fn global_default() -> Arc<Self> {
        GLOBAL_DEFAULT
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::new(Self::standard()))
    }

    pub fn set_global_default(
        policy: Self,
    ) -> Result<(), GlobalDefaultAlreadySet> {
        GLOBAL_DEFAULT
            .set(Arc::new(policy))
            .map_err(|_| GlobalDefaultAlreadySet)
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::global_default().as_ref().clone()
    }
}
```

`RedactionPolicyBuilder::new()` 从 `RedactionPolicy::default()` 复制；
`empty_builder()` 使用内部空构造器；`build_standard()` 只能使用内部空构造器，禁止递归调用
`Default`。

- [ ] **步骤 4：运行测试并确认 GREEN**

运行：

```text
cargo test --test global_default_tests --no-default-features
cargo test --test policy_tests --no-default-features
```

预期：全局测试和 policy 测试通过。

- [ ] **步骤 5：条件提交**

若已授权：

```bash
git add src/policy src/lib.rs tests/global_default_tests.rs
git commit -m "feat(策略): 支持一次性全局默认"
```

---

### Task 5：实现 RedactedText、LogSafeText、Redactor 与 Map

**文件：**
- 新建：`rs-sanitize/src/text/mod.rs`
- 新建：`rs-sanitize/src/text/redacted_text.rs`
- 新建：`rs-sanitize/src/text/log_safe_text.rs`
- 新建：`rs-sanitize/src/text/log_escape.rs`
- 新建：`rs-sanitize/src/redactor.rs`
- 新建：`rs-sanitize/tests/redactor_tests.rs`
- 新建：`rs-sanitize/tests/text_tests.rs`
- 修改：`rs-sanitize/src/lib.rs`

**接口：**
- 输入依赖：任务 4 的 `RedactionPolicy` 与任务 2 的 `MaskingPolicy`。
- 输出接口：`Redactor::{new,policy,redact,redact_map,redact_map_in_place}`、
  `RedactedText::{as_str,into_owned,escape_for_log}`、`LogSafeText`。

- [ ] **步骤 1：编写单值、Map 与日志安全失败测试**

```rust
// tests/redactor_tests.rs
use std::collections::{
    BTreeMap,
    HashMap,
};

use qubit_redact::Redactor;

#[test]
fn test_default_redactor_redacts_known_map_values() {
    let source = HashMap::from([
        ("username".to_string(), "alice".to_string()),
        ("password".to_string(), "secret".to_string()),
        ("OPENAI_API_KEY".to_string(), "sk-123".to_string()),
    ]);

    let redacted = Redactor::default().redact_map(&source);

    assert_eq!(redacted["username"], "alice");
    assert_eq!(redacted["password"], "<redacted>");
    assert_eq!(redacted["OPENAI_API_KEY"], "****");
    assert_eq!(source["password"], "secret");
}

#[test]
fn test_redact_map_in_place_supports_btree_map() {
    let mut source = BTreeMap::from([
        ("password".to_string(), "secret".to_string()),
        ("username".to_string(), "alice".to_string()),
    ]);

    Redactor::default().redact_map_in_place(&mut source);

    assert_eq!(source["password"], "<redacted>");
    assert_eq!(source["username"], "alice");
}
```

```rust
// tests/text_tests.rs
use qubit_redact::Redactor;

#[test]
fn test_escape_for_log_escapes_controls_and_bidi() {
    let text = Redactor::default().redact("message", "a\n\u{2028}\u{202e}b");
    let safe = text.escape_for_log();

    assert_eq!(safe.as_ref(), r"a\n\u{2028}\u{202e}b");
    assert_eq!(safe.to_string(), safe.as_ref());
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：

```text
cargo test --test redactor_tests --no-default-features
cargo test --test text_tests --no-default-features
```

预期：编译失败，提示 `Redactor`、`RedactedText`、`LogSafeText` 尚不存在。

- [ ] **步骤 3：实现类型化文本**

```rust
#[must_use = "use the redacted value instead of the original value"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedText<'a>(Cow<'a, str>);

impl<'a> RedactedText<'a> {
    pub(crate) fn new(value: Cow<'a, str>) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    #[must_use]
    pub fn into_owned(self) -> String {
        self.0.into_owned()
    }

    #[must_use]
    pub fn escape_for_log(self) -> LogSafeText<'a> {
        LogSafeText::from_escaped(escape_log_control_characters(self.0))
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSafeText<'a>(Cow<'a, str>);

impl Display for LogSafeText<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.as_ref())
    }
}
```

`LogSafeText::from_escaped` 必须为 `pub(crate)`；实现 `AsRef<str>`。不要为
`RedactedText` 实现 `Display`。在其 rustdoc 加一个 `compile_fail` 示例，证明
`format!("{value}")` 不可编译。

- [ ] **步骤 4：实现 Redactor 和 Map**

```rust
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redactor {
    policy: RedactionPolicy,
}

impl Redactor {
    pub const fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    pub const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    #[must_use = "use the returned redacted value"]
    pub fn redact<'a>(
        &self,
        field: &str,
        value: &'a str,
    ) -> RedactedText<'a> {
        let value = match self.policy.sensitivity_for(field) {
            Some(level) => self.policy.masking().mask(level, value),
            None => Cow::Borrowed(value),
        };
        RedactedText::new(value)
    }

    #[must_use = "use the returned redacted map"]
    pub fn redact_map<M>(&self, map: &M) -> M
    where
        for<'a> &'a M: IntoIterator<Item = (&'a String, &'a String)>,
        M: FromIterator<(String, String)>,
    {
        map.into_iter()
            .map(|(key, value)| {
                (key.clone(), self.redact(key, value).into_owned())
            })
            .collect()
    }

    pub fn redact_map_in_place<M>(&self, map: &mut M)
    where
        for<'a> &'a mut M:
            IntoIterator<Item = (&'a String, &'a mut String)>,
    {
        for (key, value) in map {
            let redacted = self.redact(key, value);
            if redacted.as_str() != value {
                *value = redacted.into_owned();
            }
        }
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(RedactionPolicy::default())
    }
}
```

为避免同时借用和赋值冲突，生产实现可用 `Cow::Owned` 分支判断，而不是比较字符串。

- [ ] **步骤 5：运行测试并确认 GREEN**

运行：

```text
cargo test --test redactor_tests --no-default-features
cargo test --test text_tests --no-default-features
cargo test --doc --no-default-features
```

预期：Map、日志转义和 compile-fail doctest 全部通过。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/text src/redactor.rs src/lib.rs tests/redactor_tests.rs tests/text_tests.rs
git commit -m "feat(核心): 增加类型化字段与 Map redaction"
```

---

### Task 6：重建 argv 与 env adapter

**文件：**
- 新建：`rs-sanitize/src/argv/mod.rs`
- 新建：`rs-sanitize/src/argv/argv_item.rs`
- 新建：`rs-sanitize/src/argv/argv_redactor.rs`
- 新建：`rs-sanitize/src/argv/redacted_argv.rs`
- 新建：`rs-sanitize/src/env/mod.rs`
- 新建：`rs-sanitize/src/env/env_redactor.rs`
- 新建：`rs-sanitize/src/env/redacted_env_pair.rs`
- 新建：`rs-sanitize/tests/argv_tests.rs`
- 新建：`rs-sanitize/tests/env_tests.rs`
- 修改：`rs-sanitize/src/lib.rs`

**接口：**
- 输入依赖：任务 5 的 `Redactor` 与 `LogSafeText`；现有 argv/env parser 行为。
- 输出接口：`ArgvItem::{plain,sensitive}`、`ArgvRedactor::{redact_items,redact_heuristically}`、
  `EnvRedactor::{redact_pair,redact_os_pair,redact_assignment}`；两个 argv 方法都接收
  `ArgvItem`，显式 level 永远优先，所有结果的 `Display` 日志安全。

- [ ] **步骤 1：编写显式 argv 和 env 失败测试**

```rust
use std::ffi::OsStr;

use qubit_redact::{
    Sensitivity,
    argv::{
        ArgvItem,
        ArgvRedactor,
    },
};

#[test]
fn test_explicit_argv_sensitivity_is_authoritative() {
    let items = [
        ArgvItem::plain(OsStr::new("sh")),
        ArgvItem::plain(OsStr::new("-c")),
        ArgvItem::sensitive(
            OsStr::new("echo secret"),
            Sensitivity::Secret,
        ),
    ];

    let rendered = ArgvRedactor::default().redact_items(items).to_string();

    assert!(!rendered.contains("echo secret"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn test_heuristic_mode_preserves_explicit_levels_and_matches_plain_options() {
    let items = [
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("raw-password")),
        ArgvItem::sensitive(
            OsStr::new("raw-explicit"),
            Sensitivity::Secret,
        ),
    ];

    let rendered = ArgvRedactor::default()
        .redact_heuristically(items)
        .to_string();

    assert!(!rendered.contains("raw-password"));
    assert!(!rendered.contains("raw-explicit"));
}
```

```rust
use qubit_redact::env::EnvRedactor;

#[test]
fn test_env_display_redacts_and_escapes() {
    let rendered = EnvRedactor::default()
        .redact_pair("PASSWORD", "secret\nnext")
        .to_string();

    assert_eq!(rendered, "PASSWORD=<redacted>");
    assert!(!rendered.contains('\n'));
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test argv_tests --test env_tests --no-default-features`

预期：编译失败，提示新 adapter 模块不存在。

- [ ] **步骤 3：实现显式 argv API**

```rust
#[derive(Debug, Clone, Copy)]
pub struct ArgvItem<'a> {
    value: &'a OsStr,
    sensitivity: Option<Sensitivity>,
}

impl<'a> ArgvItem<'a> {
    pub const fn plain(value: &'a OsStr) -> Self {
        Self { value, sensitivity: None }
    }

    pub const fn sensitive(
        value: &'a OsStr,
        sensitivity: Sensitivity,
    ) -> Self {
        Self { value, sensitivity: Some(sensitivity) }
    }
}
```

`ArgvRedactor::redact_items` 对显式 sensitivity 直接使用 `policy.masking()`；其他 item
只作为普通 argv 值，不再猜测其 CLI 角色。`redact_heuristically` 也接收 `ArgvItem`，先
尊重显式 sensitivity，再仅对剩余 plain item 复用现有 `--name=value`、`--name value`、
assignment、`--` 状态机。只有原始 argv 的调用方可用
`.map(ArgvItem::plain)` 显式选择纯启发式模式。非 UTF-8 显式敏感项使用 Secret marker。

`RedactedArgv` 内部只持有 `LogSafeText<'static>`，实现 `Display`。

- [ ] **步骤 4：实现 env API**

`EnvRedactor` 持有 `Redactor`。UTF-8 key/value 调用 `Redactor::redact` 后再
`escape_for_log`；非 UTF-8 key 或 value 对 value 使用 Secret mask。`RedactedEnvPair`
保存日志安全 name/value，并用 `NAME=VALUE` 格式实现 `Display`。

- [ ] **步骤 5：迁移现有 property tests 并确认 GREEN**

把现有 argv/env unit 与 proptest 断言迁移到新 test 文件，方法名改为 `redact_*`。

运行：

```text
cargo test --test argv_tests --test env_tests --no-default-features
cargo test --no-default-features
```

预期：显式、heuristic、非 UTF-8、确定性和 secret absence 测试全部通过。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/argv src/env src/lib.rs tests/argv_tests.rs tests/env_tests.rs
git commit -m "refactor(adapter)!: 重建 argv 和 env redactor"
```

---

### Task 7：建立 HTTP policy、BodyCapture、BodyBudget 与安全结果

**文件：**
- 新建：`rs-sanitize/src/http/mod.rs`
- 新建：`rs-sanitize/src/http/http_redaction_policy.rs`
- 新建：`rs-sanitize/src/http/http_redaction_policy_builder.rs`
- 新建：`rs-sanitize/src/http/body_budget.rs`
- 新建：`rs-sanitize/src/http/body_budget_error.rs`
- 新建：`rs-sanitize/src/http/body_capture.rs`
- 新建：`rs-sanitize/src/http/body_capture_error.rs`
- 新建：`rs-sanitize/src/http/body_redaction.rs`
- 新建：`rs-sanitize/src/http/body_redaction_status.rs`
- 新建：`rs-sanitize/src/http/body_redaction_reason.rs`
- 新建：`rs-sanitize/tests/http_tests.rs`
- 新建：`rs-sanitize/tests/http/mod.rs`
- 新建：`rs-sanitize/tests/http/body_budget_tests.rs`
- 新建：`rs-sanitize/tests/http/body_capture_tests.rs`
- 新建：`rs-sanitize/tests/http/body_redaction_tests.rs`
- 修改：`rs-sanitize/Cargo.toml`
- 修改：`rs-sanitize/src/lib.rs`

**接口：**
- 输入依赖：任务 5 的 policy/text；现有 `TextBodyPolicy`、`UrlPathPolicy`、
  `UnkeyedJsonValuePolicy` 语义。
- 输出接口：不可变 `HttpRedactionPolicy`、builder、受检 `BodyBudget` /
  `BodyCapture`、只暴露 `LogSafeText` 的 `BodyRedaction`。

- [ ] **步骤 1：编写预算和 capture invariant 失败测试**

```rust
use qubit_redact::http::{
    BodyBudget,
    BodyCapture,
    BodyCaptureError,
};

#[test]
fn test_body_budget_rejects_invalid_limits() {
    assert!(BodyBudget::new(0, 64).is_err());
    assert!(BodyBudget::new(16, 0).is_err());
    assert!(BodyBudget::new(16, BodyBudget::MIN_OUTPUT_BYTES - 1).is_err());
}

#[test]
fn test_truncated_capture_rejects_impossible_total() {
    let bytes = b"abcdef";

    assert_eq!(
        BodyCapture::truncated(bytes, Some(bytes.len())),
        Err(BodyCaptureError::InvalidTotalLength {
            captured: bytes.len(),
            total: bytes.len(),
        }),
    );
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test http_tests --no-default-features --features http`

预期：编译失败，提示新 HTTP 类型不存在。

- [ ] **步骤 3：调整临时 feature 并实现受检输入**

在最终删除旧 feature 前，先让新 `http` feature 包含全部依赖：

```toml
http = [
    "dep:form_urlencoded",
    "dep:http",
    "dep:serde_json",
    "dep:url",
]
```

实现：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyBudget {
    max_input_bytes: usize,
    max_output_bytes: usize,
}

impl BodyBudget {
    pub const MIN_OUTPUT_BYTES: usize = "<truncated>".len();

    pub fn new(
        max_input_bytes: usize,
        max_output_bytes: usize,
    ) -> Result<Self, BodyBudgetError> {
        if max_input_bytes == 0 {
            return Err(BodyBudgetError::ZeroInput);
        }
        if max_output_bytes < Self::MIN_OUTPUT_BYTES {
            return Err(BodyBudgetError::OutputTooSmall {
                minimum: Self::MIN_OUTPUT_BYTES,
                actual: max_output_bytes,
            });
        }
        Ok(Self { max_input_bytes, max_output_bytes })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyCapture<'a> {
    bytes: &'a [u8],
    total_len: Option<usize>,
    source_truncated: bool,
}
```

`complete(bytes)` 设置 `total_len = Some(bytes.len())`；`truncated(bytes, total)` 在
`Some(total) <= bytes.len()` 时返回精确错误。

- [ ] **步骤 4：实现 HTTP policy 和安全结果**

`HttpRedactionPolicy` 保存 header/query/body 三个 `RedactionPolicy`、现有三个行为 enum
以及硬安全上限 `BodyBudget`。builder 默认从同一个 `RedactionPolicy::default()` clone
三个上下文，预算为 16 KiB 输入、64 KiB 输出。

`BodyRedaction` 私有字段固定为：

```rust
pub struct BodyRedaction {
    text: LogSafeText<'static>,
    status: BodyRedactionStatus,
    captured_len: usize,
    source_len: Option<usize>,
    omitted_len: Option<usize>,
    truncated: bool,
}
```

只提供只读 metadata、`log_safe_text()`、`into_log_safe_text()` 和 `Display`；禁止
`raw_content`。输出预算包含完整 truncation marker；需要截断时先预留 marker，再把 payload
退回合法 UTF-8 boundary，保证最终 `LogSafeText::as_ref().len() <= max_output_bytes`。

- [ ] **步骤 5：运行测试并确认 GREEN**

运行：`cargo test --test http_tests --no-default-features --features http`

预期：预算、capture invariant、metadata 和日志安全结果测试通过。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add Cargo.toml src/http src/lib.rs tests/http tests/http_tests.rs
git commit -m "feat(http): 增加受检 Body 输入与预算"
```

---

### Task 8：实现单一 HttpRedactor 并迁移现有 parser

**文件：**
- 新建：`rs-sanitize/src/http/http_redactor.rs`
- 新建：`rs-sanitize/src/http/redacted_headers.rs`
- 新建：`rs-sanitize/src/http/internal/*.rs`
- 新建：`rs-sanitize/tests/http/http_redactor_tests.rs`
- 新建：`rs-sanitize/tests/http/url_redaction_tests.rs`
- 新建：`rs-sanitize/tests/http/header_redaction_tests.rs`
- 修改：`rs-sanitize/src/http/mod.rs`
- 修改：`rs-sanitize/tests/http/mod.rs`
- 迁移：`rs-sanitize/src/adapter/http/**`、`form_url_encoded.rs`、`url_sanitizer.rs` 的解析实现

**接口：**
- 输入依赖：任务 7 的 HTTP policy/input/result；现有 JSON、NDJSON、form、multipart、
  URL、Header parser。
- 输出接口：`HttpRedactor::{new,policy,redact_url,redact_url_str,redact_form,redact_headers,redact_body}`。

- [ ] **步骤 1：编写统一门面失败测试**

```rust
use http::{
    HeaderMap,
    HeaderValue,
};
use qubit_redact::http::{
    BodyCapture,
    HttpRedactor,
};
use url::Url;

#[test]
fn test_http_redactor_covers_url_headers_and_body() {
    let redactor = HttpRedactor::default();
    let url = Url::parse(
        "https://user:secret@example.test/private?api_key=raw",
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw"));

    let redacted_url = redactor.redact_url(&url);
    let redacted_headers = redactor.redact_headers(&headers);
    let redacted_body = redactor.redact_body(
        BodyCapture::complete(br#"{"password":"raw"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!redacted_url.as_ref().contains("secret"));
    assert!(!redacted_url.as_ref().contains("raw"));
    assert!(!redacted_headers.to_string().contains("Bearer raw"));
    assert!(!redacted_body.to_string().contains("raw"));
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test http_tests http_redactor --no-default-features --features http`

预期：编译失败，提示 `HttpRedactor` 尚不存在。

- [ ] **步骤 3：实现统一门面**

```rust
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRedactor {
    policy: HttpRedactionPolicy,
    header_redactor: Redactor,
    query_redactor: Redactor,
    body_redactor: Redactor,
}

impl HttpRedactor {
    pub fn new(policy: HttpRedactionPolicy) -> Self {
        Self {
            header_redactor: Redactor::new(policy.header_policy().clone()),
            query_redactor: Redactor::new(policy.query_policy().clone()),
            body_redactor: Redactor::new(policy.body_policy().clone()),
            policy,
        }
    }

    pub const fn policy(&self) -> &HttpRedactionPolicy {
        &self.policy
    }
}

impl Default for HttpRedactor {
    fn default() -> Self {
        Self::new(HttpRedactionPolicy::default())
    }
}
```

URL、form、Header 方法迁移现有算法并只返回日志安全类型。native sensitive Header
在任何 allow rule 前按 Secret 处理。

- [ ] **步骤 4：迁移 Body parser 并强制预算**

`redact_body` 的第一段代码必须先限制输入，parser 不得收到完整 slice：

```rust
let input_len = capture.bytes().len().min(
    self.policy.body_budget().max_input_bytes(),
);
let bounded = &capture.bytes()[..input_len];
let budget_truncated = input_len < capture.bytes().len();

let parsed = self.redact_body_inner(
    bounded,
    content_type,
    capture,
    budget_truncated,
);
Self::finish_body_redaction(parsed, self.policy.body_budget())
```

把现有 JSON、NDJSON、form、multipart、fallback 与 binary 算法移至
`src/http/internal`，所有字段匹配改为 `self.body_redactor.redact(field_name, value)`。malformed
structured input、file part、unkeyed scalar 和 opaque text 继续 fail-closed。
`finish_body_redaction` 先执行日志转义，再按输出预算截断并生成 metadata；成功解析的
structured body 使用 `BodyRedactionStatus::Structured`，不保留 `Sanitized` 旧术语。

- [ ] **步骤 5：迁移全部 HTTP 测试与 fuzz assertion**

把现有 `tests/adapter/http/**` 的行为断言迁移到新结果 API；测试只用
`log_safe_text()` / `Display`，禁止访问 raw content。保留 sentinel secret absence、
determinism、malformed multipart、Unicode controls 和 property tests。

运行：

```text
cargo test --test http_tests --no-default-features --features http
cargo test --no-default-features --features http
cargo check --manifest-path fuzz/Cargo.toml
```

预期：新 HTTP API 及全部迁移行为通过，fuzz target 成功编译。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/http tests/http fuzz
git commit -m "refactor(http)!: 统一到 HttpRedactor"
```

---

### Task 9：删除全部旧 API、旧 feature 与旧测试树

**文件：**
- 删除：`rs-sanitize/src/core/**`
- 删除：`rs-sanitize/src/adapter/**`
- 删除：`rs-sanitize/tests/core/**`、`rs-sanitize/tests/core_tests.rs`
- 删除：`rs-sanitize/tests/adapter/**`、`rs-sanitize/tests/adapter_tests.rs`
- 修改：`rs-sanitize/src/lib.rs`
- 修改：`rs-sanitize/Cargo.toml`
- 修改：`rs-sanitize/tests/lib_tests.rs`
- 修改：`rs-sanitize/README.md`
- 修改：`rs-sanitize/README.zh_CN.md`

**接口：**
- 输入依赖：任务 2—8 已迁移并覆盖的全部行为测试。
- 输出接口：只保留 `qubit_redact` 新 API；`default = []`；本计划阶段唯一 optional
  feature 为 `http`。

- [ ] **步骤 1：先增加旧 API 不可用的 compile-fail 契约**

在 `src/lib.rs` crate-level rustdoc 增加：

```rust
//! The pre-release sanitization façades are intentionally not available.
//!
//! ```compile_fail
//! use qubit_redact::FieldSanitizer;
//! ```
//!
//! ```compile_fail
//! use qubit_redact::HttpBodySanitizer;
//! ```
```

同时在 `tests/lib_tests.rs` 增加正向导出测试，只导入 `RedactionPolicy`、`Redactor`、
`ArgvRedactor` 和 `EnvRedactor`。

- [ ] **步骤 2：运行定向检查并确认 RED**

运行：`cargo test --doc --no-default-features`

预期：两个 `compile_fail` 示例失败，因为旧类型此时仍然可导入。

- [ ] **步骤 3：删除旧模块并收拢 Cargo feature**

删除所有已迁移的旧实现及重复测试，不建立 alias 或 wrapper。在 `Cargo.toml` 固定：

```toml
[features]
default = []
http = [
    "dep:form_urlencoded",
    "dep:http",
    "dep:serde_json",
    "dep:url",
]
```

所有四个 HTTP dependency 都设为 `optional = true`。默认 feature 下的 `[dependencies]`
不得存在非 optional 外部依赖。删除 `form`、`web` feature，也不得保留旧 feature 到新
feature 的转发。

- [ ] **步骤 4：确认新 API GREEN、旧术语消失**

运行：

```text
cargo test --doc --no-default-features
cargo test --no-default-features
cargo test --no-default-features --features http
cargo check --all-targets --all-features
```

再运行：

```bash
rg -n "qubit_sanitize|FieldSanitizer|FieldSanitizePolicy|SensitiveFields|Sanitizer|sanitize_" \
  Cargo.toml src tests fuzz README.md README.zh_CN.md
rg -n "^(form|web)\s*=" Cargo.toml
```

预期：两个搜索都无匹配；正向测试、compile-fail doctest、core 与 HTTP 测试通过。
历史设计文档不参加术语清理，因为它们记录已废弃版本。

- [ ] **步骤 5：验证默认构建零外部 runtime dependency**

运行：`cargo tree --no-default-features --edges normal --depth 1`

预期：输出只有根 package；没有 runtime child dependency。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add -A src tests Cargo.toml Cargo.lock README.md README.zh_CN.md
git commit -m "refactor(API)!: 删除旧 sanitization 门面"
```

---

### Task 10：破坏性迁移 rs-command

**文件：**
- 修改：`rs-command/Cargo.toml`
- 修改：`rs-command/Cargo.lock`
- 修改：`rs-command/src/command_argument.rs`
- 修改：`rs-command/src/command.rs`
- 修改：`rs-command/src/command_runner.rs`
- 修改：`rs-command/src/command_runner/internal/prepared_command.rs`
- 修改：`rs-command/src/command_output.rs`
- 修改：`rs-command/tests/command_argument_tests.rs`
- 修改：`rs-command/tests/command_tests.rs`
- 修改：`rs-command/tests/command_runner_tests.rs`
- 修改：`rs-command/tests/command_output_tests.rs`
- 修改：`rs-command/tests/lib_tests.rs`
- 修改：`rs-command/README.md`
- 修改：`rs-command/README.zh_CN.md`

**接口：**
- 输入依赖：任务 9 的无 feature runtime API。
- 输出接口：`CommandRunner::diagnostic_redaction_policy`；`Command` 诊断使用
  `ArgvItem`、`ArgvRedactor`、`EnvRedactor`；删除四个逐字段可变 façade 方法。

- [ ] **步骤 1：先把测试改写为新 policy 契约**

```rust
use qubit_command::{Command, CommandRunner};
use qubit_redact::{RedactionPolicy, Sensitivity};

#[test]
fn test_runner_accepts_a_complete_diagnostic_redaction_policy() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_option", Sensitivity::Secret)
        .allow_exact("username")
        .build()
        .unwrap();
    let runner = CommandRunner::new()
        .diagnostic_redaction_policy(policy.clone());

    assert_eq!(runner.configured_diagnostic_redaction_policy(), &policy);
}

#[test]
fn test_shell_payload_and_explicit_sensitive_argument_never_leak() {
    let shell = format!("{:?}", Command::shell("echo raw-shell-secret"));
    let explicit = format!("{:?}", Command::new("tool").sensitive_arg("raw-arg-secret"));

    assert!(!shell.contains("raw-shell-secret"));
    assert!(!explicit.contains("raw-arg-secret"));
}
```

同步把原有 `sensitive_field(s)` / `exclude_sensitive_field(s)` 测试改为 builder 的
`raise` / `allow_exact`。保留 `--password value`、`--token=value` 和 env assignment 的
启发式回归测试。

- [ ] **步骤 2：运行测试并确认 RED**

运行：

```text
cargo test --test command_tests
cargo test --test command_runner_tests
```

预期：依赖和新 runner API 尚不存在，编译失败。

- [ ] **步骤 3：迁移依赖、领域字段与完整 policy 注入**

manifest 使用：

```toml
qubit-redact = { version = "0.1", path = "../rs-sanitize", default-features = false }
```

`CommandArgument` 的 level 改为 `Option<Sensitivity>`。`CommandRunner` 保存不可变
`RedactionPolicy`：

```rust
impl CommandRunner {
    pub fn diagnostic_redaction_policy(
        mut self,
        policy: RedactionPolicy,
    ) -> Self {
        self.diagnostic_redaction_policy = policy;
        self
    }

    pub const fn configured_diagnostic_redaction_policy(
        &self,
    ) -> &RedactionPolicy {
        &self.diagnostic_redaction_policy
    }
}
```

删除 `sensitive_field`、`sensitive_fields`、`exclude_sensitive_field`、
`exclude_sensitive_fields`。`PreparedCommand::prepare` 和 `Command::display_command` 改为接收
`&RedactionPolicy`，方法开始时只创建一次 `Redactor` / adapter。

- [ ] **步骤 4：迁移 argv、env 与 output Debug**

`Command` 为 program、普通参数和显式敏感参数创建 `ArgvItem`；shell `-c` / `/C` payload
创建 `ArgvItem::sensitive(_, Sensitivity::Secret)`。调用
`ArgvRedactor::redact_heuristically`，使显式 level 优先、其余 item 继续执行 option-name
启发式。环境变量改用
`EnvRedactor::redact_os_pair(key.as_os_str(), value.as_os_str()).to_string()`。

`CommandOutput` 只把 import 改为 `qubit_redact::redacted_debug`；raw stdout/stderr accessor
行为不变。

- [ ] **步骤 5：确认 GREEN 并清除旧符号**

运行：

```text
cargo test --test command_argument_tests
cargo test --test command_tests
cargo test --test command_runner_tests
cargo test --test command_output_tests
cargo test
cargo check --all-targets
```

运行：

```bash
rg -n "qubit_sanitize|FieldSanitizer|SensitivityLevel|Sanitizer|sanitize_" \
  Cargo.toml src tests README.md README.zh_CN.md
```

预期：全部测试通过，搜索无匹配；诊断文本中不存在 sentinel secret。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add Cargo.toml Cargo.lock src tests README.md README.zh_CN.md
git commit -m "refactor(诊断)!: 迁移命令日志到 qubit-redact"
```

---

### Task 11：迁移 rs-config 的安全 Debug 与 env 诊断

**文件：**
- 修改：`rs-config/Cargo.toml`
- 修改：`rs-config/Cargo.lock`
- 修改：`rs-config/src/property.rs`
- 修改：`rs-config/src/source/env_config_source.rs`
- 修改：`rs-config/src/source/env_file_config_source.rs`
- 修改：`rs-config/src/source/yaml_config_source.rs`
- 修改：`rs-config/tests/property_tests.rs`
- 修改：`rs-config/tests/source/env_config_source_tests.rs`
- 修改：`rs-config/tests/source/env_file_config_source_tests.rs`
- 修改：`rs-config/tests/source/yaml_config_source_tests.rs`

**接口：**
- 输入依赖：任务 9 的 `redacted_debug` 与 `EnvRedactor`。
- 输出接口：无新的 rs-config public API；只替换内部依赖和诊断实现。

- [ ] **步骤 1：把非 UTF-8 诊断测试改成新 adapter 契约**

在 Unix 测试中保留原始非法字节 sentinel，并断言错误 `Debug` / `Display` 既不包含
sentinel，也不包含换行注入字符。增加一个普通 UTF-8 敏感 env name 的回归断言，证明
默认 policy 仍会遮盖 value。

- [ ] **步骤 2：切换 manifest 并确认 RED**

manifest 使用：

```toml
qubit-redact = { version = "0.1", path = "../rs-sanitize", default-features = false }
```

仅改 manifest 后运行：

```text
cargo test --test property_tests
cargo test --test env_config_source_tests
```

预期：旧 `qubit_sanitize` import 无法解析。

- [ ] **步骤 3：迁移实现**

- `property.rs`、env-file 和 YAML source 把 `redacted_debug` import 改为
  `qubit_redact::redacted_debug`；
- `env_config_source.rs` 使用 `EnvRedactor::default().redact_os_pair(key, value)` 生成错误
  诊断，不再传 `NameMatchMode`；
- 不启用 `derive`、`serde` 或 `http` feature；
- 不改变配置值的加载、解析或公开 accessor，redaction 只用于诊断。

- [ ] **步骤 4：确认 GREEN 并清除旧符号**

运行：

```text
cargo test --test property_tests
cargo test --test env_config_source_tests
cargo test --test env_file_config_source_tests
cargo test --test yaml_config_source_tests
cargo test
cargo check --all-targets
```

运行：

```bash
rg -n "qubit_sanitize|EnvSanitizer|NameMatchMode|sanitize_" \
  Cargo.toml src tests
```

预期：全部通过，搜索无匹配。

- [ ] **步骤 5：条件提交**

若已授权：

```bash
git add Cargo.toml Cargo.lock src tests
git commit -m "refactor(诊断)!: 迁移配置日志到 qubit-redact"
```

---

### Task 12：破坏性迁移 rs-http 并统一 Redact 术语

**文件：**
- 修改：`rs-http/Cargo.toml`
- 修改：`rs-http/Cargo.lock`
- 新建：`rs-http/src/redact/mod.rs`
- 新建：`rs-http/src/redact/log_redaction_policy.rs`
- 新建：`rs-http/src/redact/log_redaction_policy_builder.rs`
- 新建：`rs-http/src/redact/log_redactor.rs`
- 新建：`rs-http/src/redact/redacted_logger.rs`
- 新建：`rs-http/src/redact/redacted_debugger.rs`
- 新建：`rs-http/src/redact/body_preview.rs`
- 删除：`rs-http/src/sanitize/**`
- 修改：`rs-http/src/lib.rs`
- 修改：`rs-http/src/options/http_client_options.rs`
- 修改：`rs-http/src/client/http_client.rs`
- 修改：`rs-http/src/client/http_logger.rs`
- 修改：`rs-http/src/request/http_request.rs`
- 修改：`rs-http/src/request/http_request_builder.rs`
- 修改：`rs-http/src/error/http_error.rs`
- 修改：`rs-http/src/response/http_response_meta.rs`
- 修改：`rs-http/src/response/http_response_options.rs`
- 修改：`rs-http/src/response/http_response_interceptor_context.rs`
- 修改：`rs-http/src/response/http_response.rs`
- 迁移：`rs-http/tests/sanitize/**` → `rs-http/tests/redact/**`
- 修改：所有引用 `log_sanitize_policy` 或 sanitize 类型的 `rs-http/tests/**/*.rs`
- 修改：`rs-http/README.md`、`rs-http/README.zh_CN.md`
- 修改：`rs-http/doc/user_guide.en.md`、`rs-http/doc/user_guide.zh_CN.md`

**接口：**
- 输入依赖：任务 8 的 `http::HttpRedactor` 与任务 7 的 body safety types。
- 输出接口：不可变 `LogRedactionPolicy` + builder、`LogRedactor`、内部
  `RedactedLogger` / `RedactedDebugger`；所有 public 字段和方法使用 `redact` 术语。

- [ ] **步骤 1：先改写 public API 与安全预算测试**

```rust
use qubit_http::{LogRedactionPolicy, LogRedactor};
use qubit_redact::{Sensitivity, http::BodyBudget};

#[test]
fn test_log_redaction_policy_is_built_immutably() {
    let policy = LogRedactionPolicy::builder()
        .raise_header("x-tenant-secret", Sensitivity::Secret)
        .allow_query_exact("public_token")
        .body_budget(BodyBudget::new(128, 256).unwrap())
        .build()
        .unwrap();

    assert_eq!(
        policy.http_policy().header_policy()
            .sensitivity_for("x-tenant-secret"),
        Some(Sensitivity::Secret),
    );
}

#[test]
fn test_body_preview_obeys_both_presentation_and_hard_budget() {
    let policy = LogRedactionPolicy::builder()
        .body_budget(BodyBudget::new(32, 48).unwrap())
        .build()
        .unwrap();
    let redactor = LogRedactor::new(policy);
    let body = br#"{"password":"never-log-this","padding":"xxxxxxxxxxxxxxxxxxxxxxxx"}"#;

    let rendered = redactor.redact_body_preview(body, 24, Some("application/json"));

    assert!(!rendered.to_string().contains("never-log-this"));
    assert!(rendered.is_truncated());
}
```

同时把旧 public 名测试改为新名称：

```text
LogSanitizePolicy  -> LogRedactionPolicy
LogSanitizer       -> LogRedactor
sanitize_*         -> redact_*
log_sanitize_policy -> log_redaction_policy
with_log_sanitize_policy -> with_log_redaction_policy
```

配置 section key 从 `log_sanitize` 改为 `log_redaction`；没有兼容读取分支。

- [ ] **步骤 2：切换依赖并确认 RED**

manifest 使用：

```toml
qubit-redact = { version = "0.1", path = "../rs-sanitize", default-features = false, features = ["http"] }
```

运行：`cargo test --test mod redact --no-fail-fast`

预期：新 policy、redactor、字段名和配置 key 尚未实现，编译失败。

- [ ] **步骤 3：建立不可变 rs-http policy 边界**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRedactionPolicy {
    http_policy: HttpRedactionPolicy,
}

impl LogRedactionPolicy {
    pub fn builder() -> LogRedactionPolicyBuilder {
        LogRedactionPolicyBuilder::new()
    }

    pub const fn http_policy(&self) -> &HttpRedactionPolicy {
        &self.http_policy
    }
}
```

`LogRedactionPolicyBuilder` 分别持有 header/query/body 的 `RedactionPolicyBuilder` 和 HTTP
行为/预算设置，提供 `raise_*`、`override_*`、`allow_*_exact`、`allow_*_suffix`、
`text_body_policy`、`url_path_policy`、`unkeyed_json_value_policy`、`body_budget`，最终一次性
构造 `HttpRedactionPolicy`。`Default for LogRedactionPolicy` 直接包装
`HttpRedactionPolicy::default()`，不在生产代码中 unwrap builder 结果；不再有 `empty` 或
任何 `set/insert/remove/extend` 方法。

- [ ] **步骤 4：让 LogRedactor 只委托一个 HttpRedactor**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRedactor {
    policy: LogRedactionPolicy,
    http_redactor: HttpRedactor,
}

impl LogRedactor {
    pub fn new(policy: LogRedactionPolicy) -> Self {
        let http_redactor = HttpRedactor::new(policy.http_policy().clone());
        Self { policy, http_redactor }
    }
}
```

URL、header、diagnostic URL token 直接委托 `HttpRedactor`。删除 `for_debug` 的默认/custom/
exclusion 手工 merge；debug 与 trace 都使用调用时已经完成的同一 policy 快照。

保留 `BodyPreview` 作为 rs-http 的较低“展示限额”：先按调用方 `limit.max(1)` 取 prefix，
再依据完整/截断状态构造 `BodyCapture::complete` 或 `BodyCapture::truncated`。随后调用
`HttpRedactor::redact_body`，因此 core `BodyBudget` 是不可绕过的第二层硬上限。删除
`BodyLogContext` 和三套 context-specific suffix；统一消费 `BodyRedaction` metadata 与通用
truncation marker。

- [ ] **步骤 5：统一内部与 public 命名**

- `SanitizedLogger` → `RedactedLogger`，成员 `sanitizer` → `redactor`；
- `SanitizedDebugger` → `RedactedDebugger`；
- `HttpClientOptions::log_sanitize_policy` → `log_redaction_policy`；
- response option 的 `log_sanitizer` → `log_redactor`；
- request/response/error 上的 `with_log_sanitize_policy` →
  `with_log_redaction_policy`；
- 所有内部 `sanitized_*` 方法和局部变量改为 `redacted_*`；
- `src/lib.rs` 只重导出 `LogRedactionPolicy`、`LogRedactionPolicyBuilder`、`LogRedactor`。

配置解析按输入列表逐项调用 builder，再 build 一次；错误通过现有 config error 类型携带
具体 field。禁止为旧配置 key、类型或方法提供兼容分支。

- [ ] **步骤 6：确认 GREEN 与 secret-absence**

运行：

```text
cargo test --test mod redact --no-fail-fast
cargo test --test mod request --no-fail-fast
cargo test --test mod response --no-fail-fast
cargo test --test mod error --no-fail-fast
cargo test --test mod client --no-fail-fast
cargo test --test mod options --no-fail-fast
cargo test
cargo check --all-targets
```

运行：

```bash
rg -n "qubit_sanitize|LogSanitize|LogSanitizer|Sanitized|sanitize_|log_sanitize" \
  Cargo.toml src tests README.md README.zh_CN.md doc
```

预期：全部测试通过，sentinel secret absence 断言通过，搜索无匹配。

- [ ] **步骤 7：条件提交**

若已授权：

```bash
git add -A Cargo.toml Cargo.lock src tests README.md README.zh_CN.md doc
git commit -m "refactor(日志)!: 迁移 HTTP 日志到 qubit-redact"
```

---

### Task 13：更新文档并完成四仓 runtime 验收

**文件：**
- 修改：`rs-sanitize/README.md`
- 修改：`rs-sanitize/README.zh_CN.md`
- 修改：`rs-sanitize/src/lib.rs`
- 修改：`rs-sanitize/align-ci.sh`
- 修改：`rs-sanitize/ci-check.sh`
- 修改：`rs-sanitize/coverage.sh`
- 修改：`rs-sanitize/style-check.sh`
- 修改：三个下游仓库中受新名称影响的 README、rustdoc 和脚本

**接口：**
- 输入依赖：任务 9—12 已完成的新 runtime 与下游 API。
- 输出接口：可执行的 core、Map、argv/env、HTTP 示例，以及完整 feature/下游验证记录。

- [ ] **步骤 1：写 README/rustdoc 示例并先确认文档 RED**

README 中至少加入：

```rust
use std::collections::HashMap;
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

let policy = RedactionPolicy::builder()
    .raise("tenant_secret", Sensitivity::Secret)
    .build()?;
let source = HashMap::from([
    ("tenant_secret".to_owned(), "raw".to_owned()),
    ("display_name".to_owned(), "Alice".to_owned()),
]);
let redacted = Redactor::new(policy).redact_map(&source);
assert_eq!(redacted["tenant_secret"], "<redacted>");
assert_eq!(source["tenant_secret"], "raw");
# Ok::<(), Box<dyn std::error::Error>>(())
```

HTTP 示例必须带 `--features http` 说明，并从 `BodyCapture` 到 `BodyRedaction::Display`
完整演示。先运行 `cargo test --doc --all-features`；若文档尚未同步，预期因旧名称或缺失
import 失败。

- [ ] **步骤 2：同步中英文文档与 CI 脚本**

文档明确说明：全局默认只能设置一次；`builder()` 从全局默认快照开始；exact allow 与
suffix allow 的风险差异；`RedactedText` 必须显式 `escape_for_log()`；HTTP 默认关闭且只处理
有界 capture。更新 badge、package 名、docs.rs URL 和示例命令。

脚本不得假定旧 `web/form` feature；runtime 计划阶段至少执行 no-feature、http 和
all-features 三条路径。沿用仓库现有 `.rs-ci` wrapper，不复制 CI 实现。

- [ ] **步骤 3：分别格式化并静态检查四个仓库**

在每个仓库依次运行：

```text
cargo fmt --all -- --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

预期：四个仓库均为零错误、零 warning。若 formatter 修改了文件，先执行
`cargo fmt --all`，再重跑 check。

- [ ] **步骤 4：执行主 crate feature matrix**

在 `rs-sanitize` 运行：

```text
cargo test --no-default-features
cargo test --no-default-features --features http
cargo test --all-features
cargo test --doc --all-features
cargo check --manifest-path fuzz/Cargo.toml
./style-check.sh
./ci-check.sh
```

预期：全部通过。`cargo tree --no-default-features --edges normal --depth 1` 仍只显示根
package。

- [ ] **步骤 5：执行三个下游完整验证**

分别在 `rs-command`、`rs-config`、`rs-http` 运行：

```text
cargo test --all-features
cargo test --doc --all-features
./style-check.sh
./ci-check.sh
```

预期：全部通过；lockfile 中只出现 `qubit-redact 0.1.0`，不出现 `qubit-sanitize`。

- [ ] **步骤 6：执行最终静态搜索与工作树审计**

在四个仓库运行：

```bash
rg -n "qubit[_-]sanitize|FieldSanitizer|FieldSanitizePolicy|SensitiveFields|LogSanitize|Sanitizer|sanitize_" \
  Cargo.toml Cargo.lock src tests README.md README.zh_CN.md doc 2>/dev/null
git status --short
git diff --check
```

预期：术语搜索无匹配（历史设计文档除外）；`git diff --check` 无输出；工作树只包含本计划
预期文件。任何原先存在的用户改动必须保留并在交付中单列。

- [ ] **步骤 7：条件提交与阶段交付**

若用户已授权提交，按仓库分别提交剩余文档/脚本改动，不跨仓库合并提交：

```bash
git add README.md README.zh_CN.md src/lib.rs align-ci.sh ci-check.sh coverage.sh style-check.sh
git commit -m "docs: 更新 qubit-redact 使用与验证说明"
```

未授权时跳过所有提交。记录每个仓库执行过的命令和退出码，说明本计划只完成 runtime、
HTTP 与下游迁移；领域对象 derive/serde 必须继续执行第二份计划后才达到最终发布状态。

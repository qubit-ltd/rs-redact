# qubit-redact 领域对象 Derive 与 Serde 实施计划

> **面向智能体执行者：** 必须使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans，逐项实施本计划。各步骤使用复选框（`- [ ]`）语法跟踪进度。

**目标：** 在 runtime/HTTP/下游迁移完成后，为 `qubit-redact` 增加领域对象的非破坏式
redacted view、显式破坏式 redaction、`#[redact(map)]`、`#[redact(nested)]`、
`#[redact(skip)]`、可选 derive 和可选 serde。

**架构：** runtime trait 与 wrapper 放在主 crate；同仓库 `derive/` proc-macro crate 只解析
属性和生成代码，不依赖主 crate。无属性字段保持原样，只有显式 `level`、`nested`、`map`
和 `skip` 改变 redacted 路径；view 创建时快照完整 `RedactionPolicy` 并沿嵌套对象传播。

**技术栈：** Rust 1.94、edition 2024、Cargo workspace resolver 3、`syn`、`quote`、
`proc-macro2`、`proc-macro-crate`、`trybuild`、可选 `serde`、`serde_json`。

**前置计划：** 必须先完整执行
`/tmp/superpowers-qubit-redact-design.FAibmX/2026-07-20-qubit-redact-runtime-plan.md`，并确认
四仓 runtime 验收通过。本计划不与前置计划并行执行。

**设计规范：**
`/tmp/superpowers-qubit-redact-design.FAibmX/2026-07-20-qubit-redact-redesign-design.md`。

**临时工作区：** `/tmp/superpowers-qubit-redact-design.FAibmX`

**Temporary Workspace:** `/tmp/superpowers-qubit-redact-design.FAibmX`

**临时工作区清理：** 执行期间必须保留该工作区，直至两份计划均成功完成。成功后，仅在
完成相同的路径组件验证后才能删除；不得使用字符串前缀判断包含关系。必须确认：解析后的
工作区不是解析后的临时根目录；其解析后的父目录与临时根目录完全相同；其目录名以
`superpowers-` 开头；`.superpowers-session` 是空的、非符号链接的普通文件。如果执行时
存在当前仓库，还必须证明工作区与仓库完全双向不重叠：任一路径都不等于另一路径，也不
包含另一路径。否则，应记录未检测到当前仓库，并继续完成其余验证。

## 全局约束

- 本计划只修改 `rs-sanitize`；本地目录仍叫 `rs-sanitize`，package/crate 已由前置计划改为
  `qubit-redact` / `qubit_redact`。
- 不保留旧 `Sanitize` / `SanitizeMut` derive、`omit` 属性或任何兼容 alias。
- `derive` 与 `serde` 都默认关闭；关闭全部 feature 时继续保持零外部 runtime dependency。
- `http` 内部的 `serde_json` 不得隐式启用公开 `serde` feature。
- 第一版只支持 named struct；不支持 enum、union、tuple struct、unnamed field 或
  `serde(flatten)`。
- 所有 public struct、enum、trait 单独文件；生产代码禁止 `unwrap`、`expect`、`panic!`、
  `unreachable!` 和 `unsafe`。
- 所有行为变更执行 RED→GREEN→REFACTOR；每个 compile-fail fixture 必须核对定向错误，
  不得只确认“某处编译失败”。
- 不运行 `git add`、`git commit`、`git push` 或发布命令，除非用户另行明确授权。下文提交
  步骤仅在获授权后执行；未授权时记录“跳过提交”。

---

### Task 1：建立 Redact、Redacted 与值级 runtime

**文件：**
- 新建：`rs-sanitize/src/domain/mod.rs`
- 新建：`rs-sanitize/src/domain/redact.rs`
- 新建：`rs-sanitize/src/domain/redacted.rs`
- 新建：`rs-sanitize/src/domain/redact_value.rs`
- 新建：`rs-sanitize/src/domain/redacted_value.rs`
- 新建：`rs-sanitize/src/domain/internal/mod.rs`
- 新建：`rs-sanitize/src/domain/internal/nested.rs`
- 新建：`rs-sanitize/tests/domain_tests.rs`
- 新建：`rs-sanitize/tests/domain/mod.rs`
- 新建：`rs-sanitize/tests/domain/redacted_tests.rs`
- 新建：`rs-sanitize/tests/domain/redact_value_tests.rs`
- 修改：`rs-sanitize/src/lib.rs`

**接口：**
- 输入依赖：前置计划的 `RedactionPolicy`、`MaskingPolicy`、`Sensitivity`、
  `RedactedText`、`LogSafeText`。
- 输出接口：`Redact`、`Redacted<'_, T>`、`RedactValue`、`RedactedValue<'_>`。

- [ ] **步骤 1：用手写 Redact 实现定义失败契约**

```rust
use std::fmt;

use qubit_redact::{
    Redact,
    RedactValue,
    RedactionPolicy,
    Sensitivity,
};

struct ManualAccount {
    id: u64,
    password: String,
    note: String,
}

impl Redact for ManualAccount {
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("ManualAccount")
            .field("id", &self.id)
            .field(
                "password",
                &self.password.redact_value(
                    Sensitivity::Secret,
                    policy.masking(),
                ),
            )
            .field("note", &self.note)
            .finish()
    }
}

#[test]
fn test_redacted_view_is_non_destructive_and_display_is_log_safe() {
    let account = ManualAccount {
        id: 7,
        password: "raw-secret".to_owned(),
        note: "line-one\nline-two".to_owned(),
    };

    let debug = format!("{:?}", account.redacted());
    let display = account.redacted().to_string();

    assert!(!debug.contains("raw-secret"));
    assert!(!display.contains("raw-secret"));
    assert!(!display.contains('\n'));
    assert!(display.contains(r"\n"));
    assert_eq!(account.password, "raw-secret");
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test domain_tests --no-default-features`

预期：编译失败，提示 `Redact`、`RedactValue` 和 `Redacted` 尚未导出。

- [ ] **步骤 3：实现非破坏式 view 与 policy 快照**

```rust
pub trait Redact {
    fn redacted(&self) -> Redacted<'_, Self>
    where
        Self: Sized,
    {
        Redacted::new(self, RedactionPolicy::default())
    }

    fn redacted_with(
        &self,
        policy: &RedactionPolicy,
    ) -> Redacted<'_, Self>
    where
        Self: Sized,
    {
        Redacted::new(self, policy.clone())
    }

    #[doc(hidden)]
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}

#[must_use = "format or serialize the redacted view"]
pub struct Redacted<'a, T: ?Sized> {
    value: &'a T,
    policy: RedactionPolicy,
}
```

`Debug for Redacted<T>` 直接调用 `T::fmt_redacted`，保留 formatter 的 pretty 标志。
`Display` 先用 `format!("{:?}", self)` 取得只包含 redacted 字段的文本，再调用 crate 内部
日志控制字符转义并写入 formatter；禁止调用原对象的 `Display`。

- [ ] **步骤 4：实现 RedactValue 与容器语义**

```rust
pub trait RedactValue {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a>;
}

#[derive(Clone, PartialEq, Eq)]
pub enum RedactedValue<'a> {
    Text(RedactedText<'a>),
    Some(RedactedText<'a>),
    None,
}
```

为 `String`、`str`、`&str`、`Cow<'_, str>` 及其 `Option<T>` 实现。`Debug` 保持普通文本与
`Some` / `None` 容器形状；`Display` 必须日志安全。任何敏感分支都不得调用原值的
`Debug`、`Display` 或 serde。

- [ ] **步骤 5：确认 GREEN、快照和 pretty formatting**

增加测试：先创建 `redacted_with(&policy)` view，再丢弃调用方 policy clone，view 输出仍
稳定；`format!("{:#?}", view)` 保持标准多行 struct Debug；Display 把这些换行转义。

运行：

```text
cargo test --test domain_tests --no-default-features
cargo test --no-default-features
```

预期：手写实现、所有值类型、Option 语义、日志转义和原对象不变断言全部通过。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/domain src/lib.rs tests/domain tests/domain_tests.rs
git commit -m "feat(领域对象): 增加非破坏式 redacted view"
```

---

### Task 2：建立 workspace、derive crate 与最小 named-struct 宏

**文件：**
- 修改：`rs-sanitize/Cargo.toml`
- 修改：`rs-sanitize/Cargo.lock`
- 新建：`rs-sanitize/derive/Cargo.toml`
- 新建：`rs-sanitize/derive/src/lib.rs`
- 新建：`rs-sanitize/derive/src/redact_derive.rs`
- 新建：`rs-sanitize/derive/src/derive_input.rs`
- 新建：`rs-sanitize/derive/src/runtime_path.rs`
- 新建：`rs-sanitize/derive/tests/compile_tests.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/pass/basic_named_struct.rs`
- 新建：`rs-sanitize/tests/domain_derive_tests.rs`
- 修改：`rs-sanitize/src/lib.rs`

**接口：**
- 输入依赖：任务 1 的 runtime trait。
- 输出接口：可选 `derive` feature；proc-macro package `qubit-redact-derive 0.1.0`；
  `#[derive(Redact)]` 的最小 named-struct 支持。

- [ ] **步骤 1：写最小 derive 失败测试**

```rust
#![cfg(feature = "derive")]

use qubit_redact::Redact;

#[derive(Redact)]
struct PlainRecord {
    id: u64,
    name: String,
}

#[test]
fn test_derive_keeps_unmarked_fields_visible_without_recursion() {
    let value = PlainRecord {
        id: 1,
        name: "Alice".to_owned(),
    };

    assert_eq!(
        format!("{:?}", value.redacted()),
        "PlainRecord { id: 1, name: \"Alice\" }",
    );
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test domain_derive_tests --no-default-features --features derive`

预期：Cargo 提示 `derive` feature 或 `Redact` derive macro 尚不存在。

- [ ] **步骤 3：建立 Cargo workspace 与 feature**

根 manifest 增加：

```toml
[workspace]
members = ["derive"]
resolver = "3"

[features]
default = []
derive = ["dep:qubit-redact-derive"]
serde = ["dep:serde"]
http = [
    "dep:form_urlencoded",
    "dep:http",
    "dep:serde_json",
    "dep:url",
]

[dependencies]
qubit-redact-derive = { version = "0.1.0", path = "derive", optional = true }
serde = { version = "1", optional = true }
```

derive manifest 固定：

```toml
[package]
name = "qubit-redact-derive"
version = "0.1.0"
edition = "2024"
rust-version = "1.94"
publish = true

[lib]
proc-macro = true

[dependencies]
proc-macro-crate = "3"
proc-macro2 = "1"
quote = "1"
syn = { version = "2", features = ["extra-traits", "full"] }

[dev-dependencies]
qubit-redact = { version = "0.1.0", path = "..", default-features = false }
trybuild = "1"
```

主 crate 在 `cfg(feature = "derive")` 下重导出两个宏命名空间中的 `Redact`；此阶段
`RedactMut` 在任务 6 再加入。

- [ ] **步骤 4：生成最小实现并正确解析 runtime 路径**

`runtime_path.rs` 调用 `proc_macro_crate::crate_name("qubit-redact")`：

- `FoundCrate::Itself` 生成 `crate`；
- `FoundCrate::Name(name)` 生成规范化后的绝对 crate ident；
- 查找失败返回指向 derive input 的定向 `syn::Error`。

宏仅接受 named struct，并生成：

```rust
impl #impl_generics #runtime::Redact for #name #type_generics #where_clause {
    fn fmt_redacted(
        &self,
        policy: &#runtime::RedactionPolicy,
        formatter: &mut ::core::fmt::Formatter<'_>,
    ) -> ::core::fmt::Result {
        let _ = policy;
        formatter
            .debug_struct(stringify!(#name))
            #(.field(#field_names, &self.#field_idents))*
            .finish()
    }
}
```

保留 input 的 generics 和 where clause；生成代码不得导入 prelude 外名称。

- [ ] **步骤 5：确认 GREEN 与 workspace 基线**

运行：

```text
cargo test --test domain_derive_tests --no-default-features --features derive
cargo test --manifest-path derive/Cargo.toml
cargo check --workspace --all-targets
```

预期：最小 derive 与 pass fixture 通过；默认 runtime 仍不启用 proc macro。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add Cargo.toml Cargo.lock derive src/lib.rs tests/domain_derive_tests.rs
git commit -m "feat(derive): 建立 Redact 宏 crate"
```

---

### Task 3：实现 level、skip 与严格属性解析

**文件：**
- 新建：`rs-sanitize/derive/src/container_attributes.rs`
- 新建：`rs-sanitize/derive/src/field_attributes.rs`
- 新建：`rs-sanitize/derive/src/field_mode.rs`
- 新建：`rs-sanitize/derive/src/sensitivity.rs`
- 修改：`rs-sanitize/derive/src/redact_derive.rs`
- 修改：`rs-sanitize/derive/src/derive_input.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/pass/level_and_skip.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/unknown_level.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/conflicting_modes.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/unknown_attribute.rs`
- 新建：`rs-sanitize/tests/domain/derive_attribute_tests.rs`
- 修改：`rs-sanitize/tests/domain/mod.rs`

**接口：**
- 输入依赖：任务 1 的 `RedactValue`，任务 2 的 macro scaffold。
- 输出接口：字段模式 `Plain | Level(Sensitivity) | Skip`；大小写严格的四个 level；
  `skip` 从整个 redacted 表示删除字段。

- [ ] **步骤 1：写 level、skip 和“未标注不递归”失败测试**

```rust
use qubit_redact::Redact;

#[derive(Debug, Redact)]
struct Inner {
    #[redact(level = "secret")]
    secret: String,
}

struct NotDebug;

#[derive(Redact)]
struct Outer {
    #[redact(level = "medium")]
    mobile: Option<String>,
    inner: Inner,
    #[redact(skip)]
    cache: NotDebug,
}

#[test]
fn test_level_masks_skip_omits_and_plain_field_does_not_recurse() {
    let value = Outer {
        mobile: Some("13800138000".to_owned()),
        inner: Inner { secret: "raw-inner".to_owned() },
        cache: NotDebug,
    };

    let rendered = format!("{:?}", value.redacted());

    assert!(!rendered.contains("13800138000"));
    assert!(rendered.contains("raw-inner"));
    assert!(!rendered.contains("cache"));
}
```

这里断言 `raw-inner` 可见是有意的语义测试：无属性字段只使用其普通 `Debug`，即使字段
类型实现 `Redact` 也不会隐式递归。安全调用方必须显式写 `#[redact(nested)]`。

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test domain_tests derive_attribute --no-default-features --features derive`

预期：宏拒绝或忽略尚未实现的属性，测试不能按契约编译/通过。

- [ ] **步骤 3：实现唯一字段模式解析**

每个字段恰好解析为一个 `FieldMode`。`level` 只接受字符串字面量
`low|medium|high|secret`；`skip` 不接受参数。重复属性、空 `#[redact()]`、未知 key 和任意
模式组合都在属性 span 返回 `syn::Error`，错误包含类型名和字段名。

生成规则：

```text
Plain  -> .field(serialized_field_name, &self.field)
Level  -> .field(serialized_field_name,
                 &RedactValue::redact_value(&self.field, level, policy.masking()))
Skip   -> 不生成 .field，也不引用 self.field
```

`Skip` 不得给字段类型引入 `Debug` 或 redaction trait bound；用 `NotDebug` pass fixture 验证。

- [ ] **步骤 4：建立定向 UI test 基线**

`derive/tests/compile_tests.rs` 分开执行：

```rust
#[test]
fn test_pass_fixtures() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/fixtures/pass/*.rs");
}

#[test]
fn test_compile_fail_fixtures() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/fixtures/fail/*.rs");
}
```

首次运行预期生成 `wip/*.stderr`。逐个检查错误必须包含类型、字段、非法值和修复方向，再把
经核对的 stderr 移入 fixture 目录；禁止不审阅地整体接受输出。

- [ ] **步骤 5：确认 GREEN**

运行：

```text
cargo test --test domain_tests derive_attribute --no-default-features --features derive
cargo test --manifest-path derive/Cargo.toml
```

预期：level 的四种值、Option 容器、skip 无 trait bound、未标注不递归及三个错误 fixture
全部通过。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add derive tests/domain
git commit -m "feat(derive): 支持 level 与 skip 字段"
```

---

### Task 4：实现 nested 递归与显式 policy 传播

**文件：**
- 修改：`rs-sanitize/src/domain/internal/nested.rs`
- 修改：`rs-sanitize/src/domain/redact.rs`
- 修改：`rs-sanitize/derive/src/field_mode.rs`
- 修改：`rs-sanitize/derive/src/field_attributes.rs`
- 修改：`rs-sanitize/derive/src/redact_derive.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/pass/nested_containers.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/nested_without_redact.rs`
- 新建：`rs-sanitize/tests/domain/nested_tests.rs`
- 修改：`rs-sanitize/tests/domain/mod.rs`

**接口：**
- 输入依赖：任务 1 的 `Redact`，任务 3 的互斥字段模式。
- 输出接口：`#[redact(nested)]`；`Redact` for `Option<T>`、`Box<T>`、`Vec<T>`；同一
  `RedactionPolicy` 沿整条对象图传播。

- [ ] **步骤 1：写容器和显式 policy 传播失败测试**

```rust
use qubit_redact::{
    MaskPolicy,
    Redact,
    RedactionPolicy,
    Sensitivity,
};

#[derive(Redact)]
struct Credential {
    #[redact(level = "secret")]
    token: String,
}

#[derive(Redact)]
struct Session {
    #[redact(nested)]
    primary: Credential,
    #[redact(nested)]
    backup: Option<Box<Credential>>,
    #[redact(nested)]
    history: Vec<Credential>,
}

#[test]
fn test_nested_uses_the_same_explicit_policy_for_every_container() {
    let policy = RedactionPolicy::builder()
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[strict]"))
        .build()
        .unwrap();
    let session = Session {
        primary: Credential { token: "one".to_owned() },
        backup: Some(Box::new(Credential { token: "two".to_owned() })),
        history: vec![Credential { token: "three".to_owned() }],
    };

    let rendered = format!("{:?}", session.redacted_with(&policy));

    assert_eq!(rendered.matches("[strict]").count(), 3);
    assert!(!rendered.contains("one"));
    assert!(!rendered.contains("two"));
    assert!(!rendered.contains("three"));
}
```

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test domain_tests nested --no-default-features --features derive`

预期：`nested` 尚未识别，或容器没有 `Redact` 实现。

- [ ] **步骤 3：实现无分配的 nested container formatting**

- `Option<T: Redact>`：`None` 写 `None`，`Some` 用 formatter debug tuple 包裹
  `value.redacted_with(policy)`；
- `Box<T: Redact>`：透明委托内部对象的 `fmt_redacted`；
- `Vec<T: Redact>`：用 `formatter.debug_list()` 逐项加入同一 policy 的 `Redacted` view，
  不复制对象、不重读全局默认。

宏对 `Nested` 生成显式 UFCS 调用：

```rust
.field(
    #field_name,
    &#runtime::Redact::redacted_with(&self.#field_ident, policy),
)
```

禁止在展开代码中调用无参 `redacted()`。

- [ ] **步骤 4：增加“不隐式递归”的对照测试**

在同一个 outer struct 中放置一个未标注 `Credential` 和一个 `#[redact(nested)]`
`Credential`。断言前者按普通 `Debug` 显示 raw sentinel，后者不显示。这一测试固定：
`nested` 是唯一递归开关，字段类型本身实现 `Redact` 不足以触发递归。

- [ ] **步骤 5：确认 GREEN 与定向 trait error**

运行：

```text
cargo test --test domain_tests nested --no-default-features --features derive
cargo test --manifest-path derive/Cargo.toml
```

预期：直接对象、Option、Box、Vec、显式 mask policy 传播通过；缺少 `Redact` 的 fixture
错误定位到具体 nested 字段并建议实现 `Redact` 或删除 `nested`。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/domain derive tests/domain
git commit -m "feat(derive): 支持显式 nested redaction"
```

---

### Task 5：实现惰性 RedactedMap 与 #[redact(map)]

**文件：**
- 新建：`rs-sanitize/src/domain/redact_map_value.rs`
- 新建：`rs-sanitize/src/domain/redact_map_value_mut.rs`
- 新建：`rs-sanitize/src/domain/redacted_map.rs`
- 修改：`rs-sanitize/src/domain/mod.rs`
- 修改：`rs-sanitize/src/lib.rs`
- 修改：`rs-sanitize/derive/src/field_mode.rs`
- 修改：`rs-sanitize/derive/src/field_attributes.rs`
- 修改：`rs-sanitize/derive/src/redact_derive.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/pass/map_fields.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/map_with_wrong_value.rs`
- 新建：`rs-sanitize/tests/domain/map_tests.rs`
- 新建：`rs-sanitize/tests/domain_global_map_tests.rs`
- 修改：`rs-sanitize/tests/domain/mod.rs`

**接口：**
- 输入依赖：前置计划的 `Redactor::redact`，任务 1 的 view policy 快照。
- 输出接口：`RedactMapValue`、`RedactMapValueMut`、`RedactedMap<'_, M>`、
  `#[redact(map)]`。

- [ ] **步骤 1：写显式 policy、原对象不变和全局默认失败测试**

```rust
use std::collections::{BTreeMap, HashMap};

use qubit_redact::{Redact, RedactionPolicy, Sensitivity};

#[derive(Redact)]
struct Event {
    #[redact(map)]
    metadata: HashMap<String, String>,
    unmarked: BTreeMap<String, String>,
}

#[test]
fn test_map_uses_view_policy_lazily_and_unmarked_map_stays_plain() {
    let policy = RedactionPolicy::empty_builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()
        .unwrap();
    let event = Event {
        metadata: HashMap::from([
            ("tenant_secret".to_owned(), "raw-map-secret".to_owned()),
            ("label".to_owned(), "visible".to_owned()),
        ]),
        unmarked: BTreeMap::from([
            ("tenant_secret".to_owned(), "raw-unmarked".to_owned()),
        ]),
    };

    let rendered = format!("{:?}", event.redacted_with(&policy));

    assert!(!rendered.contains("raw-map-secret"));
    assert!(rendered.contains("visible"));
    assert!(rendered.contains("raw-unmarked"));
    assert_eq!(event.metadata["tenant_secret"], "raw-map-secret");
}
```

`tests/domain_global_map_tests.rs` 只能包含一个测试：安装一次全局 default，调用
`event.redacted()`，断言 Map 使用该 default；该文件作为独立 integration-test 进程，避免
污染其他测试。

- [ ] **步骤 2：运行测试并确认 RED**

运行：

```text
cargo test --test domain_tests map --no-default-features --features derive
cargo test --test domain_global_map_tests --no-default-features --features derive
```

预期：`map` mode 和 runtime wrapper 尚不存在。

- [ ] **步骤 3：实现泛型 Map runtime 与惰性 view**

```rust
pub trait RedactMapValue {
    fn fmt_redacted_map(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut Formatter<'_>,
    ) -> fmt::Result;
}

pub trait RedactMapValueMut {
    fn redact_map_in_place(&mut self, policy: &RedactionPolicy);
}

#[must_use = "format or serialize the redacted map view"]
pub struct RedactedMap<'a, M: ?Sized> {
    map: &'a M,
    policy: RedactionPolicy,
}
```

为满足以下约束的容器做 blanket implementation，因此同时覆盖 `HashMap<String, String>`、
`BTreeMap<String, String>` 和同类自定义容器：

```rust
for<'a> &'a M: IntoIterator<Item = (&'a String, &'a String)>
for<'a> &'a mut M: IntoIterator<Item = (&'a String, &'a mut String)>
```

`Debug` 用 `formatter.debug_map()` 逐项调用 `Redactor::new(policy.clone()).redact(key, value)`；
wrapper 不预先 collect、不 clone 整张 Map。`Display` 只格式化 redacted Debug 后做日志转义。

- [ ] **步骤 4：生成 map 字段代码**

宏的 `Map` 分支生成 `RedactedMap::new(&self.field, policy.clone())`，且不使用字段自身的
唯一 sensitivity。属性解析把 `map` 与 `level`、`nested`、`skip` 视为互斥；错误明确说明
Map value 是按运行期 key 与完整 policy 判断。

- [ ] **步骤 5：确认 GREEN 与不复制契约**

增加一个自定义 Map wrapper，在 `IntoIterator for &Wrapper` 中记录遍历次数；断言创建
`redacted_with` 时计数仍为 0，真正 `Debug` 时才遍历一次。运行：

```text
cargo test --test domain_tests map --no-default-features --features derive
cargo test --test domain_global_map_tests --no-default-features --features derive
cargo test --manifest-path derive/Cargo.toml
```

预期：HashMap、BTreeMap、自定义容器、全局/显式 policy、原对象不变、惰性遍历与错误
fixture 全部通过。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/domain src/lib.rs derive tests/domain tests/domain_global_map_tests.rs
git commit -m "feat(derive): 支持按 key redaction 的 Map 字段"
```

---

### Task 6：实现 RedactMut 与显式破坏式转换

**文件：**
- 新建：`rs-sanitize/src/domain/redact_mut.rs`
- 新建：`rs-sanitize/src/domain/redact_value_mut.rs`
- 修改：`rs-sanitize/src/domain/internal/nested.rs`
- 修改：`rs-sanitize/src/domain/mod.rs`
- 修改：`rs-sanitize/src/lib.rs`
- 新建：`rs-sanitize/derive/src/redact_mut_derive.rs`
- 修改：`rs-sanitize/derive/src/lib.rs`
- 修改：`rs-sanitize/derive/src/derive_input.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/pass/redact_mut.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/redact_mut_borrowed_field.rs`
- 新建：`rs-sanitize/tests/domain/redact_mut_tests.rs`
- 修改：`rs-sanitize/tests/domain/mod.rs`

**接口：**
- 输入依赖：任务 3—5 的四种字段模式与 Map mut trait。
- 输出接口：`RedactMut`、`RedactValueMut`、`#[derive(RedactMut)]`；无参方法快照全局
  default，`*_with` 方法使用显式 policy。

- [ ] **步骤 1：写六个操作语义的失败测试**

```rust
use std::collections::HashMap;

use qubit_redact::{RedactMut, RedactionPolicy, Sensitivity};

#[derive(Clone, RedactMut)]
struct MutableAccount {
    id: u64,
    #[redact(level = "secret")]
    password: String,
    #[redact(map)]
    metadata: HashMap<String, String>,
    #[redact(skip)]
    internal_note: String,
}

#[test]
fn test_to_redacted_changes_only_the_clone() {
    let policy = RedactionPolicy::empty_builder()
        .raise("token", Sensitivity::Secret)
        .build()
        .unwrap();
    let original = MutableAccount {
        id: 3,
        password: "raw-password".to_owned(),
        metadata: HashMap::from([("token".to_owned(), "raw-token".to_owned())]),
        internal_note: "unchanged".to_owned(),
    };

    let copy = original.to_redacted_with(&policy);

    assert_eq!(original.password, "raw-password");
    assert_eq!(original.metadata["token"], "raw-token");
    assert_ne!(copy.password, "raw-password");
    assert_ne!(copy.metadata["token"], "raw-token");
    assert_eq!(copy.id, 3);
    assert_eq!(copy.internal_note, "unchanged");
}
```

另测 `redact_in_place`、`redact_in_place_with`、`into_redacted`、
`into_redacted_with`、`to_redacted`，以及 `nested` 的 Option/Box/Vec 传播。

- [ ] **步骤 2：运行测试并确认 RED**

运行：`cargo test --test domain_tests redact_mut --no-default-features --features derive`

预期：trait 和 derive macro 尚不存在。

- [ ] **步骤 3：实现 runtime 默认方法与值级 mutation**

```rust
pub trait RedactMut {
    fn redact_in_place_with(&mut self, policy: &RedactionPolicy);

    fn redact_in_place(&mut self) {
        let policy = RedactionPolicy::default();
        self.redact_in_place_with(&policy);
    }

    fn into_redacted_with(mut self, policy: &RedactionPolicy) -> Self
    where
        Self: Sized,
    {
        self.redact_in_place_with(policy);
        self
    }

    fn into_redacted(self) -> Self
    where
        Self: Sized,
    {
        let policy = RedactionPolicy::default();
        self.into_redacted_with(&policy)
    }

    fn to_redacted_with(&self, policy: &RedactionPolicy) -> Self
    where
        Self: Clone + Sized,
    {
        self.clone().into_redacted_with(policy)
    }

    fn to_redacted(&self) -> Self
    where
        Self: Clone + Sized,
    {
        let policy = RedactionPolicy::default();
        self.to_redacted_with(&policy)
    }
}
```

`RedactValueMut` 为 `String`、`Cow<'_, str>` 及其 `Option<T>` 实现；`str` / `&str` 不实现，
避免虚假的原地能力。为 `Option<T>`、`Box<T>`、`Vec<T>` 实现 nested `RedactMut`。

- [ ] **步骤 4：生成四种字段模式的 mutation**

```text
Plain  -> 不生成代码
Skip   -> 不生成代码
Level  -> RedactValueMut::redact_value_in_place(
              &mut self.field, level, policy.masking())
Nested -> RedactMut::redact_in_place_with(&mut self.field, policy)
Map    -> RedactMapValueMut::redact_map_in_place(&mut self.field, policy)
```

宏只生成 required `redact_in_place_with`；其他五个方法统一使用 runtime 默认实现，确保
全局 default 恰好在每次顶层调用开始时快照一次。

- [ ] **步骤 5：确认 GREEN 与借用字段 compile-fail**

运行：

```text
cargo test --test domain_tests redact_mut --no-default-features --features derive
cargo test --manifest-path derive/Cargo.toml
```

预期：六个方法、未标注/skip 不变、nested、map 和显式 policy 通过；`&str` level fixture
错误定位到字段并说明改用 owned `String`、移除 `RedactMut` 或自定义 `RedactValueMut`。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add src/domain src/lib.rs derive tests/domain
git commit -m "feat(derive): 增加显式破坏式 RedactMut"
```

---

### Task 7：实现可选 serde runtime 与 #[redact(serde)]

**文件：**
- 修改：`rs-sanitize/Cargo.toml`
- 修改：`rs-sanitize/Cargo.lock`
- 新建：`rs-sanitize/src/domain/redact_serialize.rs`
- 新建：`rs-sanitize/src/domain/redact_map_serialize.rs`
- 新建：`rs-sanitize/src/domain/internal/redacted_serialize.rs`
- 新建：`rs-sanitize/src/private.rs`
- 修改：`rs-sanitize/src/domain/redacted.rs`
- 修改：`rs-sanitize/src/domain/redacted_value.rs`
- 修改：`rs-sanitize/src/domain/redacted_map.rs`
- 修改：`rs-sanitize/src/domain/internal/nested.rs`
- 修改：`rs-sanitize/src/domain/mod.rs`
- 修改：`rs-sanitize/src/lib.rs`
- 新建：`rs-sanitize/derive/src/serde_attributes.rs`
- 新建：`rs-sanitize/derive/src/serde_rename_rule.rs`
- 修改：`rs-sanitize/derive/src/container_attributes.rs`
- 修改：`rs-sanitize/derive/src/field_attributes.rs`
- 修改：`rs-sanitize/derive/src/redact_derive.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/crates/serde_disabled/Cargo.toml`
- 新建：`rs-sanitize/derive/tests/fixtures/crates/serde_disabled/src/main.rs`
- 新建：`rs-sanitize/derive/tests/serde_feature_guard_tests.rs`
- 新建：`rs-sanitize/tests/domain_serde_compile_tests.rs`
- 新建：`rs-sanitize/tests/fixtures/domain_serde/pass/redacted_serde.rs`
- 新建：`rs-sanitize/tests/fixtures/domain_serde/fail/serde_flatten.rs`
- 新建：`rs-sanitize/tests/fixtures/domain_serde/fail/serde_flatten.stderr`
- 新建：`rs-sanitize/tests/fixtures/domain_serde/fail/serde_serialize_with.rs`
- 新建：`rs-sanitize/tests/fixtures/domain_serde/fail/serde_serialize_with.stderr`
- 新建：`rs-sanitize/tests/fixtures/domain_serde/fail/nested_without_serialize.rs`
- 新建：`rs-sanitize/tests/fixtures/domain_serde/fail/nested_without_serialize.stderr`
- 新建：`rs-sanitize/tests/domain/serde_tests.rs`
- 修改：`rs-sanitize/tests/domain/mod.rs`

**接口：**
- 输入依赖：任务 1—6 的 view/value/nested/map runtime。
- 输出接口：可选 `serde` feature；隐藏 `RedactSerialize` / `RedactMapSerialize` hook；仅对
  声明 `#[redact(serde)]` 的 struct 实现 `Serialize for Redacted<'_, T>` 所需能力。

- [ ] **步骤 1：写 serde 形状与 secret-absence 失败测试**

```rust
use std::collections::BTreeMap;

use qubit_redact::Redact;
use serde::Serialize;

#[derive(Redact, Serialize)]
#[redact(serde)]
#[serde(rename_all = "camelCase")]
struct ApiAccount {
    account_id: u64,
    #[redact(level = "secret")]
    password: Option<String>,
    #[redact(map)]
    metadata: BTreeMap<String, String>,
    #[redact(skip)]
    internal_note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nickname: Option<String>,
}

#[test]
fn test_redacted_serde_preserves_shape_and_never_serializes_raw_values() {
    let value = ApiAccount {
        account_id: 9,
        password: Some("raw-password".to_owned()),
        metadata: BTreeMap::from([
            ("api_key".to_owned(), "raw-api-key".to_owned()),
        ]),
        internal_note: "raw-internal".to_owned(),
        nickname: None,
    };

    let json = serde_json::to_string(&value.redacted()).unwrap();

    assert!(json.contains(r#""accountId":9"#));
    assert!(!json.contains("raw-password"));
    assert!(!json.contains("raw-api-key"));
    assert!(!json.contains("internalNote"));
    assert!(!json.contains("nickname"));
}
```

再增加 nested struct、`Option::None`、`serde(rename = "wire_name")`、`serde(skip)` 和 serializer
error 传播测试。原始对象自己的 `Serialize` 输出保持完全不变。

- [ ] **步骤 2：运行 feature 组合并确认 RED**

运行：

```text
cargo test --test domain_tests serde --no-default-features --features derive,serde
cargo test --no-default-features --features serde
```

预期：`#[redact(serde)]`、hidden hook 或 `Serialize for Redacted` 尚不存在。

- [ ] **步骤 3：实现 feature-gated runtime，避免错误雪崩**

在主 crate 定义两版同名 hidden macro：

```rust
#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_serde {
    ($($tokens:tt)*) => { $($tokens)* };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_serde {
    ($($tokens:tt)*) => {
        compile_error!(
            "#[redact(serde)] requires the `serde` feature of qubit-redact"
        );
    };
}
```

derive 把完整 serde impl 放进此 macro；feature 关闭时 token 被丢弃，只留下这一条定向
错误，不继续解析缺失的 serde 路径。

feature 开启时，`private.rs` 以 `#[doc(hidden)] pub mod __private` 重导出 serde，并导出：

```rust
pub trait RedactSerialize {
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}
```

`Serialize for Redacted<T>` 只要求 `T: RedactSerialize` 并委托该 hook；不实现
`Deserialize`。为 `RedactedValue`、`RedactedMap` 和 nested Option/Box/Vec wrapper 实现
对应 lazy serialization，任何 serializer error 原样向上传播。

根 manifest 的 `[dev-dependencies]` 增加 `serde_json = "1"` 和 `trybuild = "1"`。
`tests/domain_serde_compile_tests.rs` 只在 `derive,serde` 同时启用时运行：pass/fail fixture
放在 `tests/fixtures/domain_serde`。feature-disabled 场景放在带独立 `[workspace]` 的
`derive/tests/fixtures/crates/serde_disabled`，其 dependency 只启用 `derive`。这样即使外层
执行 `cargo test --workspace --all-features`，子 Cargo 进程也不会因 workspace feature
unification 意外启用 serde。

```rust
#![cfg(all(feature = "derive", feature = "serde"))]

#[test]
fn test_redacted_serde_ui() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/fixtures/domain_serde/pass/*.rs");
    tests.compile_fail("tests/fixtures/domain_serde/fail/*.rs");
}
```

`serde_feature_guard_tests.rs` 用 `std::process::Command` 执行独立 fixture 的 `cargo check`，
断言失败 stderr 中该文本只对应一条 primary `error:`：
“`#[redact(serde)] requires the serde feature of qubit-redact`”，并且不包含
“unresolved import serde”或同类次生错误。

- [ ] **步骤 4：实现 serde 属性白名单与字段生成**

只在 struct 声明 `#[redact(serde)]` 时解析 serde 属性：

- 两个 proc-macro 入口都注册 `attributes(redact, serde)`，使 helper 属性合法；
  `RedactMut` 接受但忽略 container 的 `#[redact(serde)]`，只由 `Redact` 生成 serialize hook；

- container：`serde(rename_all = "camelCase")` 等 serde 标准 rename rule；
- field：`serde(rename = "wire_name")`、`skip`、`skip_serializing`、
  `skip_serializing_if = "path"`；
- `flatten`、`serialize_with`、`with` 及其他改变结构/算法的属性返回定向错误；
- 未声明 `#[redact(serde)]` 时，serde 属性完全不影响 `Redact` / `RedactMut`。

生成代码使用 `serde::ser::SerializeStruct`：先按所有 skip 条件计算准确 field count，再按
以下规则 serialize：

```text
Plain  -> 原字段的 Serialize
Level  -> RedactedValue 的 Serialize
Nested -> 同一 policy 的 nested Redacted wrapper
Map    -> 同一 policy 的 RedactedMap
Skip   -> 不进入结果
```

`skip_serializing_if` 在 raw 字段引用上判断是否跳过，但通过后仍只序列化 redacted wrapper。

- [ ] **步骤 5：确认 GREEN、feature guard 与 serde 隔离**

运行：

```text
cargo test --test domain_tests serde --no-default-features --features derive,serde
cargo test --no-default-features --features serde
cargo test --no-default-features --features derive
cargo test --manifest-path derive/Cargo.toml
cargo test --test domain_serde_compile_tests --no-default-features --features derive,serde
cargo tree --no-default-features --edges normal --depth 1
```

预期：serde shape、rename、skip、nested、map、None、error propagation 全部通过；feature
关闭 feature 的独立 fixture 只有一条定向错误；只开 `derive` 不引入 serde；关闭全部
feature 仍无外部
runtime dependency。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add Cargo.toml Cargo.lock src derive tests
git commit -m "feat(serde): 增加可选 redacted serialization"
```

---

### Task 8：补齐 generics、依赖重命名与编译期诊断矩阵

**文件：**
- 修改：`rs-sanitize/derive/src/derive_input.rs`
- 修改：`rs-sanitize/derive/src/runtime_path.rs`
- 修改：`rs-sanitize/derive/src/redact_derive.rs`
- 修改：`rs-sanitize/derive/src/redact_mut_derive.rs`
- 新建：`rs-sanitize/derive/src/field_assertion.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/pass/generics_and_lifetimes.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/enum.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/union.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/tuple_struct.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/empty_attribute.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/duplicate_attribute.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/fail/map_without_map_trait.rs`
- 修改：`rs-sanitize/tests/fixtures/domain_serde/fail/nested_without_serialize.rs`
- 新建：`rs-sanitize/derive/tests/fixtures/crates/renamed_dependency/Cargo.toml`
- 新建：`rs-sanitize/derive/tests/fixtures/crates/renamed_dependency/src/main.rs`
- 新建：`rs-sanitize/derive/tests/renamed_dependency_tests.rs`
- 修改：所有 `rs-sanitize/derive/tests/fixtures/fail/*.stderr`

**接口：**
- 输入依赖：任务 2—7 的完整宏行为。
- 输出接口：稳定的 named-struct/generics 支持；crate dependency alias 支持；每类非法输入
  都有唯一、可行动的错误。

- [ ] **步骤 1：先列齐 pass/fail 矩阵并确认 RED**

pass fixture 覆盖：type parameter、lifetime、const generic、已有 where clause、字段类型额外
bound，以及 runtime dependency 被重命名。fail fixture 覆盖：

```text
enum / union / tuple struct
未知、空、重复属性
未知 level
level + nested / level + map / map + skip 等冲突
nested 缺少 Redact
map 缺少 RedactMapValue
RedactMut level 缺少 RedactValueMut
RedactMut nested 缺少 RedactMut
serde feature 关闭
serde flatten / serialize_with
serde nested 缺少 RedactSerialize
```

运行：

```text
cargo test --manifest-path derive/Cargo.toml
cargo test --test domain_serde_compile_tests --no-default-features --features derive,serde
```

预期：新增 fixture 中尚未定向处理的场景失败，trybuild 生成待核对 stderr。

- [ ] **步骤 2：保留用户 generics 与 where clause**

所有 impl 使用 `split_for_impl()`；只为实际被字段模式引用的类型引入 bound。`skip` 字段不
引入任何 bound，Plain 只引入格式/serde 所需 bound，`level`、`nested`、`map` 分别通过
runtime trait 约束。不得给整个 type parameter 无条件增加 `Debug + Redact + Serialize`。

- [ ] **步骤 3：生成带字段上下文的静态断言**

为每个非 Plain/Skip 字段生成使用字段 span 的零成本 helper，helper 名包含规范化后的类型名
和字段名，例如：

```text
__qubit_redact_Account_password_requires_RedactValueMut
__qubit_redact_Account_metadata_requires_RedactMapValue
```

这样 rustc trait-bound error 同时显示所需 trait、类型名和字段名。宏自行检测的输入错误使用
`syn::Error::new_spanned`，消息还必须包含修复动作，例如“choose exactly one of level,
nested, map, or skip”。

- [ ] **步骤 4：验证 dependency alias**

fixture manifest 使用：

```toml
[package]
name = "redact-renamed-dependency-fixture"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
redaction-runtime = { package = "qubit-redact", path = "../../../../..", default-features = false, features = ["derive"] }
```

源文件只引用 `redaction_runtime::{Redact, RedactionPolicy}`。测试运行：

```rust
#[test]
fn test_renamed_runtime_dependency_compiles() {
    let status = std::process::Command::new(env!("CARGO"))
        .args([
            "check",
            "--manifest-path",
            "tests/fixtures/crates/renamed_dependency/Cargo.toml",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}
```

测试代码允许 `unwrap`，生产代码不允许。`proc-macro-crate` 必须把 package 名解析到依赖
alias `redaction_runtime`，不得硬编码 `::qubit_redact`。

- [ ] **步骤 5：逐项核对 stderr 并确认 GREEN**

对每个 `wip/*.stderr`：确认错误指向用户字段/类型 span、没有 raw sensitive fixture value、
没有大段无关 follow-on error；逐个移动到对应 fixture。然后运行：

```text
cargo test --manifest-path derive/Cargo.toml
cargo test --test domain_tests --no-default-features --features derive,serde
cargo test --test domain_serde_compile_tests --no-default-features --features derive,serde
cargo check --workspace --all-targets --all-features
```

预期：全部 pass/fail fixture、dependency alias、generics、runtime integration 通过；stderr
在相同 toolchain 下稳定。

- [ ] **步骤 6：条件提交**

若已授权：

```bash
git add derive tests
git commit -m "test(derive): 完善泛型与编译错误契约"
```

---

### Task 9：文档、workspace CI、feature matrix 与最终发布验收

**文件：**
- 修改：`rs-sanitize/README.md`
- 修改：`rs-sanitize/README.zh_CN.md`
- 修改：`rs-sanitize/src/lib.rs`
- 修改：`rs-sanitize/Cargo.toml`
- 修改：`rs-sanitize/align-ci.sh`
- 修改：`rs-sanitize/ci-check.sh`
- 修改：`rs-sanitize/coverage.sh`
- 修改：`rs-sanitize/style-check.sh`
- 新建：`rs-sanitize/docs/superpowers/specs/2026-07-20-qubit-redact-redesign-design.md`
- 新建：`rs-sanitize/docs/superpowers/plans/2026-07-20-qubit-redact-runtime-plan.md`
- 新建：`rs-sanitize/docs/superpowers/plans/2026-07-20-qubit-redact-domain-derive-plan.md`

**接口：**
- 输入依赖：本计划任务 1—8 和前置 runtime 计划全部完成。
- 输出接口：完整 domain/Map/derive/serde 文档、workspace-aware CI、可发布 feature matrix 和
  三个下游的最终验证记录。

- [ ] **步骤 1：先写可编译领域对象示例并确认文档 RED**

中英文 README 与 crate rustdoc 至少包含：

```rust
use std::collections::HashMap;
use qubit_redact::{Redact, RedactionPolicy, Sensitivity};

#[derive(Redact)]
struct Account {
    id: u64,
    #[redact(level = "secret")]
    password: String,
    #[redact(map)]
    metadata: HashMap<String, String>,
}

let policy = RedactionPolicy::empty_builder()
    .raise("api_key", Sensitivity::Secret)
    .build()?;
let account = Account {
    id: 1,
    password: "raw-password".to_owned(),
    metadata: HashMap::from([
        ("api_key".to_owned(), "raw-key".to_owned()),
    ]),
};
let output = format!("{:?}", account.redacted_with(&policy));
assert!(!output.contains("raw-password"));
assert!(!output.contains("raw-key"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

另写 `nested`、`skip`、`RedactMut`、`#[redact(serde)]` 示例，并明确标注所需 feature。
先运行 `cargo test --doc --all-features`；若示例还未接入/修正，预期失败。

- [ ] **步骤 2：写清语义边界与 feature**

文档必须明确：

- 无属性字段原样输出且永不隐式递归；
- `nested` 才递归，`map` 才按动态 key 判断 value；
- `skip` 从 redacted Debug/Display/serde 表示移除字段，但原对象和 `RedactMut` 都不改它；
- `redacted()` 快照全局默认，`redacted_with` 使用显式 policy，nested/map 沿用同一快照；
- 第一版 Map 不支持字段级 `policy = "custom_policy"`；不同 policy 用领域 newtype + nested；
- `to_redacted` 会短暂存在第二份原始敏感数据；高敏感场景优先 `redact_in_place` 或
  `into_redacted`；
- `derive`、`serde`、`http` 独立且默认关闭；第一版只支持 named struct；
- `Redacted` 不实现 Deserialize，原对象的 Debug/Display/Serialize 不受影响。

- [ ] **步骤 3：把批准文档纳入仓库并更新 CI wrapper**

用 `apply_patch` 把临时工作区中的设计文档和两份计划复制到上述仓库路径，保持正文一致，
从而在最终安全清理临时工作区后仍有项目内记录。

CI/style/coverage wrapper 必须覆盖 workspace 的 runtime 与 derive crate；保留现有 `.rs-ci`
委托方式。至少运行 no feature、derive、serde、derive+serde、http、all features 和 derive
crate UI tests。不得让 HTTP 的 serde_json 激活公开 serde runtime 测试路径。

- [ ] **步骤 4：执行主 crate 完整 feature matrix**

在 `rs-sanitize` 运行：

```text
cargo fmt --all -- --check
cargo check -p qubit-redact --all-targets --no-default-features
cargo test -p qubit-redact --no-default-features
cargo test -p qubit-redact --no-default-features --features derive
cargo test -p qubit-redact --no-default-features --features serde
cargo test -p qubit-redact --no-default-features --features derive,serde
cargo test -p qubit-redact --no-default-features --features http
cargo test --workspace --all-features
cargo test --doc --all-features
cargo test --manifest-path derive/Cargo.toml
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml
./style-check.sh
./ci-check.sh
```

预期：全部通过、零 warning。再次运行
`cargo tree -p qubit-redact --no-default-features --edges normal --depth 1`，预期只有根
package。

- [ ] **步骤 5：执行安全与语义验收搜索**

运行：

```bash
rg -n "derive\(Sanitize|SanitizeMut|sanitize_|\#\[sanitize|redact\(omit\)|FieldSanitizer|SensitiveFields" \
  Cargo.toml src derive tests README.md README.zh_CN.md
rg -n "default\s*=\s*\[[^]]+\]" Cargo.toml
git diff --check
```

预期：旧 API/属性搜索无匹配；default feature 为空；diff whitespace 检查无输出。另用测试
日志搜索所有 sentinel（`raw-password`、`raw-key` 等），只有 test input/断言可出现，任何
snapshot 或实际输出不得出现。

- [ ] **步骤 6：重跑三个下游并检查 lockfile**

分别在 `rs-command`、`rs-config`、`rs-http` 运行：

```text
cargo fmt --all -- --check
cargo test --all-features
cargo test --doc --all-features
cargo clippy --all-targets --all-features -- -D warnings
./style-check.sh
./ci-check.sh
```

预期：三个下游仍全部通过；lockfile 使用 `qubit-redact 0.1.0`；没有下游意外启用
`derive`、`serde`，只有 rs-http 启用 `http`。

- [ ] **步骤 7：检查 package 内容和发布顺序，不执行发布**

运行：

```text
cargo package --manifest-path derive/Cargo.toml --allow-dirty
cargo package --list -p qubit-redact
```

预期：derive package 可打包，主 package 列表包含 runtime、README、LICENSE 和 workspace
所需 metadata，不包含 fuzz corpus、临时文件或 secret fixture output。记录发布顺序：先
`qubit-redact-derive 0.1.0`，再 `qubit-redact 0.1.0`；本步骤绝不运行 `cargo publish`。

- [ ] **步骤 8：工作树审计、条件提交和临时工作区清理**

分别在四个仓库运行 `git status --short` 和 `git diff --check`。工作树只能包含两份计划
列出的文件；保留并单列任何原有用户改动。

若用户已授权提交，在 `rs-sanitize` 提交剩余文档/脚本：

```bash
git add Cargo.toml Cargo.lock README.md README.zh_CN.md src derive tests docs \
  align-ci.sh ci-check.sh coverage.sh style-check.sh
git commit -m "docs: 完成 qubit-redact 领域对象与发布说明"
```

未授权时跳过提交。仅当两份计划的所有验收均成功且三份临时文档已进入仓库后，按本计划
开头的路径组件、marker 和双向不重叠规则验证临时工作区，再删除该临时工作区；验证任一项
失败就保留目录并报告原因。

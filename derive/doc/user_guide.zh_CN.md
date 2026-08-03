# qubit-redact-derive 用户手册

[README](../README.zh_CN.md) · [English User Guide](user_guide.md) · [运行时用户手册](../../doc/user_guide.zh_CN.md) · [derive API](https://docs.rs/qubit-redact-derive)

Qubit Redact Derive 将字段级脱敏决策生成到 Rust 领域类型的实现中。它与
[`qubit-redact`](https://docs.rs/qubit-redact) 运行时配合：运行时负责策略和掩码，
本 crate 将这些决策应用到 struct 与 enum。

## 目录

- [安装与示例运行方式](#安装与示例运行方式)
- [核心概念](#核心概念)
- [1. 用 `Redact` 创建借用视图](#1-用-redact-创建借用视图)
- [2. 选择字段处理方式](#2-选择字段处理方式)
- [3. 支持的 struct 与 enum](#3-支持的-struct-与-enum)
- [4. 用 `RedactMut` 替换逻辑值](#4-用-redactmut-替换逻辑值)
- [5. 生成 `Debug` 和 `Display`](#5-生成-debug-和-display)
- [6. 用 Serde 序列化脱敏视图](#6-用-serde-序列化脱敏视图)
- [7. 解析依赖与排查错误](#7-解析依赖与排查错误)
- [安全边界与验证](#安全边界与验证)

## 安装与示例运行方式

包名是 `qubit-redact-derive`，宏的 Rust 导入路径是
`qubit_redact_derive`。生成的实现依赖运行时 crate，因此 `qubit-redact` 必须是
直接依赖。本手册中可运行的 Rust 示例都是完整的 `main.rs`：使用该节依赖并运行
`cargo run`。

```toml
[dependencies]
qubit-redact = { version = "0.6", features = ["serde"] }
qubit-redact-derive = "0.6"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

`serde` feature 只在使用 `#[redact(serde)]` 时需要；基本的 `Redact` 与
`RedactMut` derive 不要求 Serde。

## 核心概念

`Redact` 和 `RedactMut` 既是宏名也是运行时 trait 名，应分别导入以明确边界：

```rust
use qubit_redact::{Redact as _, RedactMut as _};
use qubit_redact_derive::{Redact, RedactMut};
```

`#[derive(Redact)]` 实现运行时 `Redact` trait。调用 `redacted()` 返回
`Redacted<T>`：这是惰性的借用视图，持有策略快照而不修改 `T`。
`redacted_with(&policy)` 使用显式策略快照。

`#[derive(RedactMut)]` 实现 `RedactMut`。调用 `redact_in_place()` 使用当前默认
策略；调用 `redact_in_place_with(&policy)` 使用显式快照并替换对象内的逻辑值。

| 边界 | 首选方式 | 原因 |
| --- | --- | --- |
| Debug 输出、错误上下文、结构化诊断 | `Redact` | 源对象保持可用，脱敏视图清晰可见。 |
| 后续 API 必须接收逻辑脱敏后的对象 | `RedactMut` | 修改在调用点明确且有意。 |
| 测试或子系统需要策略隔离 | `redacted_with` 或 `redact_in_place_with` | 调用点拥有策略，而不是使用进程默认值。 |

## 1. 用 `Redact` 创建借用视图

从一个已知敏感等级的字段开始：

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Login {
    account: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let login = Login {
        account: "ada".to_owned(),
        password: "raw-password".to_owned(),
    };

    let diagnostic = format!("{:?}", login.redacted());
    assert!(diagnostic.contains("ada"));
    assert!(!diagnostic.contains("raw-password"));
    assert_eq!(login.password, "raw-password");
}
```

`Redacted<T>` 格式化生成的脱敏表示。它不是第二个领域对象，也不提供 `T` 的拥有式替换。

## 2. 选择字段处理方式

每个字段可以没有 `redact` 属性，或恰好选择下列一种模式。组合模式、重复模式、向裸模式
传递参数，或使用空的 `#[redact()]` 都会产生编译错误。

| 属性 | 不可变 `Redact` 行为 | 可变 `RedactMut` 行为 | 所需运行时能力 |
| --- | --- | --- | --- |
| 无 | 使用普通 `Debug` 格式化字段。 | 保持字段不变。 | 格式化需要 `Debug`。 |
| `level = "low"`、`"medium"`、`"high"` 或 `"secret"` | 使用选定掩码。 | 用选定掩码替换逻辑值。 | `RedactValue` / `RedactValueMut`。 |
| `skip` | 省略字段。 | 保持字段不变。 | 无。 |
| `nested` | 通过嵌套值的 `Redact` 实现格式化。 | 调用嵌套的 `RedactMut`。 | `Redact` / `RedactMut`。 |
| `map` | 使用 key 和完整策略处理文本 key Map 的值。 | 原地处理这些 Map 值。 | `RedactMapValue` / `RedactMapValueMut`。 |

敏感等级拼写区分大小写且必须小写；仅接受 `low`、`medium`、`high` 和 `secret`。

下面的类型展示所有不可变模式：

```rust
use std::collections::BTreeMap;

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Request {
    request_id: String,
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
    #[redact(map)]
    metadata: BTreeMap<String, String>,
}

fn main() {
    let request = Request {
        request_id: "req-7".to_owned(),
        token: "raw-token".to_owned(),
        internal_note: "operator-only".to_owned(),
        metadata: BTreeMap::from([("api_key".to_owned(), "raw-key".to_owned())]),
    };
    let output = format!("{:?}", request.redacted());
    assert!(output.contains("req-7"));
    assert!(!output.contains("raw-token"));
    assert!(!output.contains("operator-only"));
}
```

不要期待未标记字段被发现或递归检查。字段包含领域对象时使用 `nested`；字段是支持的
文本 key Map 时使用 `map`。

## 3. 支持的 struct 与 enum

`Redact` 支持具名、tuple、unit struct，也支持具名、tuple、unit variant 的 enum。
字段属性可用于所有受支持形态。

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
enum Event {
    Login {
        user: String,
        #[redact(level = "secret")]
        token: String,
    },
    ApiKey(#[redact(level = "secret")] String),
    Ready,
}

fn main() {
    let event = Event::Login {
        user: "ada".to_owned(),
        token: "raw-token".to_owned(),
    };
    assert!(!format!("{:?}", event.redacted()).contains("raw-token"));
    assert_eq!(format!("{:?}", Event::Ready.redacted()), "Ready");
}
```

union 会被拒绝。生成实现会保留泛型参数和 where clause，Rust 会验证字段满足所选属性需要的
能力。

## 4. 用 `RedactMut` 替换逻辑值

`RedactMut` 使用相同字段语法。它只修改标记为 `level`、`nested` 或 `map` 的字段；
普通字段和 `skip` 字段保持不变。

```rust
use qubit_redact::RedactMut as _;
use qubit_redact_derive::RedactMut;

#[derive(RedactMut)]
struct Credentials {
    account: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    audit_note: String,
}

fn main() {
    let mut value = Credentials {
        account: "ada".to_owned(),
        password: "raw-password".to_owned(),
        audit_note: "keep".to_owned(),
    };

    value.redact_in_place();
    assert_eq!(value.password, "<redacted>");
    assert_eq!(value.audit_note, "keep");
}
```

可使用 `into_redacted()` 消费并处理值，或使用 `to_redacted()` 克隆并处理值。两者都不是
内存擦除。

## 5. 生成 `Debug` 和 `Display`

在 `Redact` derive 上，`#[redact(debug)]` 与 `#[redact(display)]` 会为原类型生成
格式化实现。两者均通过当前进程级默认策略的快照格式化。

```rust
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(debug, display)]
struct Secret {
    #[redact(level = "secret")]
    value: String,
}

fn main() {
    let value = Secret {
        value: "raw-secret".to_owned(),
    };
    assert!(!format!("{value:?}").contains("raw-secret"));
    assert!(!format!("{value}").contains("raw-secret"));
}
```

若类型已有对应 trait 实现，不要请求生成 `Debug` 或 `Display`。需要非默认策略的边界应避免
生成格式化，改为格式化 `value.redacted_with(&policy)`。

## 6. 用 Serde 序列化脱敏视图

序列化必须显式选择：在 `Redact` derive 上添加 `#[redact(serde)]`，启用
`qubit-redact` 的 `serde` feature，并直接声明 `serde`。 `Redacted<T>` 只序列化，
不反序列化。

```rust
use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "camelCase")]
struct LoginEvent {
    account_name: String,
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event = LoginEvent {
        account_name: "ada".to_owned(),
        token: "raw-token".to_owned(),
        internal_note: "operator-only".to_owned(),
    };

    let json = serde_json::to_string(&event.redacted())?;
    assert!(json.contains("accountName"));
    assert!(!json.contains("raw-token"));
    assert!(!json.contains("internal_note"));
    Ok(())
}
```

宏保留当前脱敏表示需要的 Serde wire 控制项：

| Serde 控制项 | 脱敏行为 |
| --- | --- |
| `rename`、`rename_all`、`rename_all_fields` | 应用配置后的字段和 variant 名称。 |
| `skip`、`skip_serializing`、`skip_serializing_if` | 按序列化规则省略字段；`skip` 和 `skip_serializing` 也可省略 enum variant。 |
| 外部标记 | 保留默认 enum wire 形态。 |
| `tag` | 保留内部标记 enum 输出。 |
| `tag` 与 `content` | 保留相邻标记 enum 输出。 |
| `untagged` | 保留无标记 enum 输出。 |

未启用运行时 `serde` feature 或出现不支持的 Serde 控制项时，宏会给出定向错误。

## 7. 解析依赖与排查错误

生成代码通过 Cargo 元数据解析运行时。重命名运行时依赖同样有效：

```toml
[dependencies]
redaction = { package = "qubit-redact", version = "0.6" }
qubit-redact-derive = "0.6"
```

派生宏仍会生成正确路径。不要依赖传递性的运行时依赖；应在使用 derive 的 package 中直接添加它。

| 情况 | 处理方式 |
| --- | --- |
| 无法解析运行时 crate | 直接添加 `qubit-redact`，或修正其 Cargo 重命名。 |
| `#[redact(serde)]` 提示缺少 feature | 启用 `qubit-redact = { features = ["serde"] }`。 |
| 派生 package 中 Serde 导入失败 | 直接添加具有所需 derive feature 的 `serde` 依赖。 |
| 属性被拒绝 | 每个字段只使用一种模式：`level = "..."`、`skip`、`nested` 或 `map`；容器控制项必须是裸属性。 |
| trait-bound 错误指向字段 | 选择该字段类型支持的模式，或实现所需运行时 trait。 |
| union 被拒绝 | 只在受支持的 struct 与 enum 形态上派生。 |

## 安全边界与验证

- 宏不是秘密探测器。每个敏感字段都必须标记，或位于显式的 nested/map 边界内。
- `Redact` 只保护通过 `redacted()` 或 `redacted_with()` 获得的表示；记录原始值仍然不安全。
- `skip` 从派生视图或序列化的脱敏输出中移除字段，但保留源对象。
- `RedactMut` 只进行逻辑替换；需要内存擦除时请使用专用的 zeroization 设计。
- `#[redact(debug)]`、`#[redact(display)]` 以及每一次默认策略调用都应视为进程级策略决策。

发布 derive 或示例变更前，运行：

```bash
cargo test --all-features
./ci-check.sh
```

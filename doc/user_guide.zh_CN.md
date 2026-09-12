# qubit-redact 用户手册

[README](../README.zh_CN.md) · [英文用户手册](user_guide.md) · [derive 说明](../derive/README.zh_CN.md) · [API 文档](https://docs.rs/qubit-redact/0.8/qubit_redact/)

本手册适用于 **qubit-redact 0.8**，需要 **Rust 1.94 或更新版本**，
面向应用和库作者：先跑通日志与业务序列化共存，再配置领域类型、输入格式和预算。
手册中的每个 Rust 代码块都是完整程序，可单独替换测试应用的 `src/main.rs` 运行。

## 目录

- [概念模型](#概念模型)
- [安装](#安装)
- [快速上手：脱敏单个字段](#快速上手脱敏单个字段)
- [实战场景：登录诊断](#实战场景登录诊断)
- [选择输出与理解视图](#选择输出与理解视图)
- [选择入口与使用时机](#选择入口与使用时机)
- [组合一条诊断消息](#组合一条诊断消息)
- [Composer 与 batch 的分工](#composer-与-batch-的分工)
- [领域类型与字段参考](#领域类型与字段参考)
- [输入格式与集成](#输入格式与集成)
- [进阶用法](#进阶用法)
- [标准策略与 strict 策略](#标准策略与-strict-策略)
- [字段规则、floor 与 allow](#字段规则floor-与-allow)
- [预算计量与 0.8 迁移](#预算计量与-08-迁移)
- [错误与诊断](#错误与诊断)
- [处理不完整结果](#处理不完整结果)
- [排障](#排障)
- [并发与运行时约束](#并发与运行时约束)
- [限制与最佳实践](#限制与最佳实践)
- [延伸阅读](#延伸阅读)

## 手册目标与读者

适用于 qubit-redact 0.8 的应用和库作者：先跑通日志和业务序列化共存，再配置领域类型、输入格式和预算。

## 概念模型

qubit-redact 将源对象、策略快照和渲染结果分开处理。`RedactedView` 借用源对象，
在每次格式化或序列化时应用创建时的策略；`redact_text()` 和 `to_json()` 则立即执行。
批处理把多个输入放进同一份事务预算。上述结果都不会修改源对象。

## 安装

下面的依赖配置支持本节所有示例。

<!-- redact-example: kind=cargo features=derive,serde,json -->
```toml
[dependencies]
qubit-redact = { version = "0.8", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## 快速上手：脱敏单个字段

在配置领域类型之前，先确认标量路径是否满足需求。内置 standard 策略已把 `password` 等常见
字段名识别为 secret，无需启用可选 feature，也无需自定义规则。将下面程序保存为 `src/main.rs`
后执行 `cargo run` 即可验证。

<!-- redact-example: kind=cargo features=none -->
```toml
[dependencies]
qubit-redact = "0.8"
```

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;

fn main() {
    let output = Redactor::standard().redact_field("password", "raw-secret");
    assert_eq!(output.text().as_str(), "<redacted>");
    assert_eq!(output.summary().completion(), qubit_redact::RedactionCompletion::Complete);
}
```

内存中的源字符串不会被修改；只有渲染出的诊断文本会脱敏。日志字段、错误上下文键或快速试验
都可以先走这条路径，再决定是否投入 derive 标注。

## 实战场景：登录诊断

下面的登录对象保留内存中的原始密码，但诊断格式化和直接业务序列化都必须隐藏密码。
`#[redact(serde)]` 显式选择这一序列化边界。后续示例还会说明：业务序列化确实需要原值时，
如何将它与脱敏诊断分开。

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact)]
#[redact(serde, debug)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let login = Login { user: "ada".into(), password: "raw-secret".into() };
    let redactor = Redactor::standard();
    let view = redactor.redact_view(&login);
    assert!(!format!("{view}").contains("raw-secret"));
    assert!(!format!("{login:?}").contains("raw-secret"));
    let json = redactor.to_json(&login).expect("redacted JSON");
    assert_eq!(json, r#"{"user":"ada","password":"<redacted>"}"#);
    assert!(!serde_json::to_string(&login).expect("business JSON").contains("raw-secret"));
    let output = redactor.redact_text(&login);
    assert!(!output.text().as_str().contains("raw-secret"));
}
```

## 选择输出与理解视图

| 入口 | 返回值 | 何时执行 |
| --- | --- | --- |
| `redact_view(&value)` | `RedactedView<'a, T>` | 每次格式化或序列化时 |
| `redact_text(&value)` | `RedactionTextOutput` | 立即执行，包含最终文本和摘要 |
| `to_json(&value)` | `Result<String, serde_json::Error>` | 立即序列化视图 |

视图借用源对象并拥有策略快照，不是脱敏后的业务对象，也不缓存源内容。
多次序列化分别从源对象执行，绝不会把上次掩码结果作为下一次输入；每次使用独立预算。
它支持 Display/Debug；结构化序列化要求 derive 生成的 `RedactSerialize` capability，
不会退化成 Debug 字符串，普通调用方无需手写隐藏 trait。
源对象具有内部可变状态时，后续使用可能观察到新值；策略仍保持创建时快照。

`redact_text()` 的 `output.text()` 可以直接展示，不再次脱敏。
`to_json()` 与直接序列化 view 共用字段投影和策略，但额外限制最终 JSON 字节数。
源状态相同且两者均成功时输出一致。它只遍历一次，传播序列化或预算错误，不返回半截 JSON。
成功可能包含结构降级后的安全替代，因此不是完整性保证。
它遵循领域标注；`redact_json(text)` 则解析输入 JSON 并按 JSON key 分类，两者不可混用。

## 选择入口与使用时机

| 需求 | 入口 | 典型场景 |
| --- | --- | --- |
| 脱敏单个命名字段 | `redact_field(field, value)` | 日志行、错误键、快速诊断 |
| 固定策略下的延迟格式化 | `redact_view(&value)` | 传入 `format!`、tracing 字段或自定义 serializer |
| 立即获取最终文本 | `redact_text(&value)` | 写入日志或 HTTP body 前拼好字符串 |
| 紧凑脱敏 JSON | `to_json(&value)` | 不依赖外部 serializer 的结构化诊断 |
| 借用 JSON 输入 | `redact_json(text)` / `redact_json_value(&value)` | 载荷本身已是 JSON |
| 多值共享预算 | `diagnostic_batch()` | HTTP 各组成部分、argv/env、多字段事件 |
| 一条有序消息 | `text_composer()` | 前缀 + 字段 + 领域对象拼成一行 |
| 只分类不渲染 | `inspect_*` | 网关准入、校验器、预检 |

优先选最窄的入口。view 推迟到格式化时才执行；composer 与 batch 共享事务预算，但发布的结果
形态不同。inspection 不会格式化字段内容；成功时 `usage().output_bytes()` 为 0。

## 组合一条诊断消息

`text_composer()` 在同一份预算下构造一条有序诊断字符串。可链式拼接字面量、按策略分类的
字段、领域对象、argv 片段和环境变量赋值；调用一次 `finish()` 得到 `RedactionTextOutput`。

<!-- redact-example: kind=run features=none -->
```rust
use std::ffi::OsStr;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

fn main() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("password");
        })
        .expect("valid field rule")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    let output = redactor
        .text_composer()
        .literal("request password=")
        .field("password", "super-secret")
        .literal(" argv=")
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .finish();
    assert_eq!(output.text().as_str(), "request password=<redacted> argv=[\"client\"]");
    assert!(!output.text().as_str().contains("super-secret"));
}
```

每次 `finish()` 都会从新的预算账本开始。可以复用同一个 `Redactor`，但不要复用已 finalize
的 `RedactionTextOutput`——库不会回头修改它。

## Composer 与 batch 的分工

两者共享同一份策略快照和同一份事务预算，但解决的问题不同。

| 模型 | 发布结果 | 适用场景 |
| --- | --- | --- |
| `text_composer()` | 一条拼接好的 `RedactionTextOutput` | 单行日志或错误消息 |
| `diagnostic_batch()` | 通过 `finish_with_marker` 解析的逐项句柄 | 需要分别查看 URL、header、body 等部分 |

batch 句柄只对创建它的 batch 有效。在后续 batch 的 `finish_with_marker` 中解析旧句柄，
会得到已转义的降级 marker，而不是原文。composer 不提供句柄；整条消息作为一个整体成功或降级。

环境变量同样如此：行内展示用 `.env(...)`，需要逐项检查时用 batch 的 `redact_env(name, value)`。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;
use std::ffi::OsStr;

fn main() {
    let redactor = Redactor::standard();
    let composed = redactor
        .text_composer()
        .env(|env| {
            env.pair("MODE", "debug");
            env.os_pairs([(OsStr::new("REGION"), OsStr::new("ap-east-1"))]);
        })
        .finish();
    let mut batch = redactor.diagnostic_batch();
    let password = batch.redact_env("PASSWORD", "raw-secret");
    let output = batch.finish_with_marker("<incomplete>");
    assert_eq!(composed.text().as_str(), r#"MODE=debug["REGION=ap-east-1"]"#);
    assert_eq!(output.text(password).as_str(), "PASSWORD=<redacted>");
}
```

## 领域类型与字段参考

| 字段属性 | 作用与类型要求 |
| --- | --- |
| 无属性 | 文本使用普通 `Debug`；启用 runtime 的 `serde` feature 后，只要字段支持 Serde，视图即可按生成的脱敏投影序列化。 |
| `level = "low"/"medium"/"high"/"secret"` | 对各叶子应用最终等级；支持基本标量、`RedactScalar` 和支持的递归容器。 |
| `level = "...", display` | 显式按 `Display` 文本处理，不要求该类型实现 `Debug` 或普通 `Serialize`。 |
| `skip` | 启用时省略；disabled 恢复字段。 |
| `nested` | 委托 `Redact`；结构化输出使用嵌套值生成的视图投影。 |
| `map` | 支持 key 为 `String`、`&str`、`Cow<str>` 的 `HashMap`/`BTreeMap`，以及外层 `Option`；value 需具备等级能力，放行文本还需 `Debug`。 |
| `map_key_level = "..."` | 固定每个 key 的等级，value 保持普通输出。 |
| `map_key_level = "...", map_value_level = "..."` | 分别固定 key、value 等级。 |
| `keyed_by = key` | 按实现 `AsRef<str>` 的兄弟 key 分类，仅用于具名字段；value 需具备等级能力和 `Debug`。 |
| `json` | 支持 JSON `String`/`str`/`Cow<str>`、已解析 `serde_json::Value`、引用和 `Option`；需要 `json` feature。 |

容器属性包括 `debug`、`display`、`serde`、`transparent` 和 `crate = path`。
runtime 的 `serde` feature 会为每个派生类型生成 `redact_view()` 的结构化脱敏能力。
`#[redact(serde)]` 额外让源对象自身的普通 `Serialize` 输出脱敏；未标注时，单独派生的普通
`Serialize` 保持原有行为。需要启用 runtime 的 `serde` feature；生成代码本身不要求直接依赖 Serde。
只有自己的代码使用 Serde trait 或派生宏时，才需直接声明 `serde`。
`transparent` 要求恰好一个字段，委托该字段的表示，本身不声明标量能力。
`debug` 不应与普通 `Debug` 派生同时使用，`serde` 不应与普通 `Serialize` 派生同时使用。

### 选择序列化边界

启用 runtime 的 `serde` feature 后，`Redact` 总会生成供 `redact_view()` 和 `to_json()`
使用的脱敏投影。源类型本身不必实现 `Serialize`，投影即可使用。字段只需满足其脱敏模式的
要求：未标注字段通常需要 `Serialize`；`level = "...", display` 只需 `Display`，并输出脱敏
字符串。

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact, serde::Serialize)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let login = Login { user: "ada".into(), password: "raw-secret".into() };
    assert!(serde_json::to_string(&login).expect("business JSON").contains("raw-secret"));
    assert!(!Redactor::standard().to_json(&login).expect("redacted JSON").contains("raw-secret"));
}
```

只有需要让源对象被直接序列化时也输出脱敏内容，才添加 `#[redact(serde)]`。类型既没有普通
`Serialize`，也没有 `#[redact(serde)]` 时，不能直接序列化源对象；只要生成的投影能够序列化
字段，view 和 `to_json()` 仍可用。若字段缺少所需能力，view 的文本格式化仍可用；但结构化
序列化该 view 或调用 `to_json()` 会产生编译期 trait-bound 错误。

内置等级叶子包括字符串、字符、布尔、整数、浮点数，以及 `bigdecimal` 下的 BigDecimal。
等级容器包括引用、Option、Vec、切片、数组、Box/Rc/Arc、VecDeque、LinkedList、集合、堆、
标准 Map 和最长 12 项 tuple。Map 的普通 level 处理 value，保留 key；要隐藏 key 使用对应属性。
文本 Map 放行路径和 keyed_by 需要 Debug；仅使用 level 的 RedactScalar 不要求 Debug。

### 手写业务键包装的嵌套值

手写 `Redact` 实现时，如果一个 `Redact + Debug` 子值由业务键决定策略，可调用
`fields.keyed_nested(display_name, business_key, value)`。业务键公开时，该方法会递归调用子值，
因此子字段规则、JSON 遍历和 inspection 仍然生效；业务键敏感时，整个载荷作为一个值掩码；
disabled 策略则输出原值。这避免了公开包装通过 `Debug` 回退泄露内部 secret。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{Redact, RedactionWriter, Sensitivity};

struct NamedPayload { name: String, payload: Payload }
#[derive(Debug)]
struct Payload { password: String }

impl Redact for Payload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.sensitive_at_least(Sensitivity::Secret, "password", || &self.password);
        });
    }
}

impl Redact for NamedPayload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("NamedPayload", |fields| {
            fields.unredacted("name", || &self.name);
            fields.keyed_nested("payload", &self.name, &self.payload);
        });
    }
}

fn main() {
    let payload = NamedPayload {
        name: "public".into(),
        payload: Payload { password: "raw-secret".into() },
    };
    let output = qubit_redact::Redactor::standard().redact_text(&payload);
    assert!(!output.text().as_str().contains("raw-secret"));
}
```

Serde 支持 rename/rename_all、枚举 tag/content/untagged、transparent、skip、skip_serializing、
skip_serializing_if。支持普通或 skip 字段上的 with/serialize_with；不能与观察原值的敏感模式组合。
flatten 不受支持。JSON 文本字段序列化后仍是字符串，已解析 Value 字段保留 JSON 结构。

### 标量 newtype

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, RedactScalar, Redactor};

#[derive(RedactScalar)]
struct Id(u64);

#[derive(RedactScalar)]
struct UserId { value: String }

#[derive(Redact)]
#[redact(serde)]
struct Account {
    #[redact(level = "secret")]
    id: Id,
    #[redact(level = "secret")]
    user_id: UserId,
}

fn main() {
    let account = Account { id: Id(42), user_id: UserId { value: "raw-id".into() } };
    assert_eq!(Redactor::standard().to_json(&account).expect("account JSON"),
        r#"{"id":"<redacted>","user_id":"<redacted>"}"#);
}
```

### 第三方 Display 类型

显式选择文本表示。High/Secret 不触发 Display，Low/Medium 和 disabled 按需格式化，
资源预算仍生效；disabled 下也保持这里明确选择的字符串表示。

<!-- redact-example: kind=run features=derive,serde,json -->
```rust
use qubit_redact::{Redact, Redactor};

struct ExternalId(u64);
impl std::fmt::Display for ExternalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(value) = self;
        write!(f, "external-{value}")
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Event {
    #[redact(level = "secret", display)]
    id: ExternalId,
}

fn main() {
    let event = Event { id: ExternalId(42) };
    assert_eq!(Redactor::standard().to_json(&event).expect("event JSON"),
        r#"{"id":"<redacted>"}"#);
}
```

### 等级与策略优先级

| 决策来源 | 运行时策略能否提高等级 |
| --- | --- |
| derive 的 level、Display level、map key/value level | 不能：显式等级为最终等级 |
| 手写 fields.sensitive_at_least(level, ...) | 可以：参数是最低等级 |
| map、keyed_by、redact_field | 按运行时分类规则决定 |
| 未标注字段、unmarked | 不分类，保持普通输出 |

默认掩码：Low 保留首尾各两个字符，短串全部隐藏；Medium 保留末尾一个字符；
High 输出 `****`；Secret 输出 `<redacted>`。例如 `abcdef` 的 Low 为 `ab****ef`，
Medium 为 `*******f`。业务类型负责选择正确等级，strict 不覆盖显式声明。

| 等级 | 示例值 | 掩码结果 |
| --- | --- | --- |
| Low | `abcdef` | `ab****ef` |
| Low | `ab` | `<redacted>`（短串全部隐藏） |
| Medium | `abcdef` | `*******f` |
| High | 任意 | `****` |
| Secret | 任意 | `<redacted>` |

### 多个值共享预算

HTTP 的 URL、headers、body 或进程的 argv、env 往往属于同一条诊断事件。使用 batch，
这些值共用一次资源预算；分别调用单值方法或多次使用视图则各用一份预算。
批次按加入顺序消耗额度，后面的项可能因前面的项耗尽预算而降级。
`finish_with_marker(marker)` 给不完整项及无效/跨批次句柄统一返回已转义 marker。
`finish()` 使用默认标记 `<redaction incomplete>`。`summary()` 是整批摘要，不是逐项审计接口。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;

fn main() {
    let mut batch = Redactor::standard().diagnostic_batch();
    let user = batch.redact_field("user", "ada");
    let password = batch.redact_field("password", "raw-secret");
    let output = batch.finish_with_marker("<incomplete>");
    assert_eq!(output.text(user).as_str(), "ada");
    assert_eq!(output.text(password).as_str(), "<redacted>");
}
```

## 输入格式与集成

### 渲染其他格式

运行时为 JSON 文本和值、URI、HTTP header/query、环境变量、argv 和进程描述提供有界脱敏。
每种格式保留自身解析和转义规则，同时共享策略决策和事务预算。

解析 JSON 时输入只被借用且保持不变：

<!-- redact-example: kind=run features=json -->
```rust
use qubit_redact::Redactor;

fn main() {
    let value = serde_json::json!({"password": "raw", "visible": "shown"});
    let output = Redactor::standard().redact_json_value(&value);
    let inspection = Redactor::standard().inspect_json_value(&value);
    assert!(!output.text().as_str().contains("raw"));
    assert_eq!(value["password"], "raw");
    let _ = inspection;
}
```

`DiagnosticRedactionBatch::redact_json_value` 以及其他批处理方法共享预算。调用
`finish_with_marker` 后，句柄选择完整项的文本或已转义的降级标记；
`summary()` 描述整个批次。

JSON 文本只解析一次，解析过程同时完成结构准入并构造 admitted tree。非法 JSON 或遍历
超限时会整体安全降级。借用 `Value` 的路径不会复制、转成字符串或修改调用方对象；
领域实现可用 `fields.json_value("payload", &value)` 写入不带额外字符串引号的 JSON 值。
序列实现则应逐项调用 `items.json_value_item(&value)`，它会执行同样的递归 JSON 策略。对于
声明数据类型为 JSON 的下游集合，这一点尤其重要：每一项都必须按 JSON 结构遍历，不能作为
不透明标量格式化。

<!-- redact-example: kind=run features=json -->
```rust
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Documents(Vec<serde_json::Value>);

impl Redact for Documents {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        let Self(documents) = self;
        writer.sequence(|items| {
            items.for_each(documents, |items, value| {
                items.json_value_item(value);
            });
        });
    }
}

fn main() {
    let documents = Documents(vec![serde_json::json!({"password": "raw"})]);
    let output = qubit_redact::Redactor::standard().redact_text(&documents);
    assert!(!output.text().as_str().contains("raw"));
}
```

JSON 文本采用 `qubit-json` 的明确数字契约：负整数必须装入 `i64`，非负整数必须装入 `u64`，
小数/指数必须得到有限 `f64`。越界文本沿用安全降级的无效 JSON 路径；serde_json 旧私有
Number 标记键是普通对象键。

### 在同一个批处理中处理完整 HTTP 交换

本示例需要启用 runtime 的 `http` feature，并在依赖中添加 `http = "1"`。

同一条诊断事件的 URL、header 和捕获 body 应进入同一个事务：

<!-- redact-example: kind=run features=http -->
```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

fn main() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-token"));
    let content_type = HeaderValue::from_static("application/json");
    let body = br#"{"user":"ada","password":"raw-password"}"#;

    let mut batch = Redactor::standard().diagnostic_batch();
    let url = batch.redact_http_url("https://example.test/login?token=raw-token");
    let headers_handle = batch.redact_http_headers(&headers);
    let body_handle = batch.redact_http_body(BodyCapture::complete(body), Some(&content_type));
    let output = batch.finish_with_marker("<redaction incomplete>");

    for handle in [url, headers_handle, body_handle] {
        assert!(!output.text(handle).as_str().contains("raw-"));
    }
}
```

`BodyCapture::complete` 表示全部源字节均已提供；`BodyCapture::prefix` 记录已知的完整长度，
`BodyCapture::truncated_unknown` 则表示存在缺失字节，但缺失数量未知。来源截断与输出截断是
不同状态，前者通过 `RedactionReason::SourceTruncated` 报告。不要把不完整 body 伪装成
complete capture。

### 接受 URI 前先执行检查

本示例需要启用 runtime 的 `uri` feature。

需要拒绝 URI，而不只是把它转成安全文本时，可以使用检查 API。发现敏感数据和返回错误都应
按安全降级处理：

<!-- redact-example: kind=run features=uri -->
```rust
use qubit_redact::Redactor;

fn main() {
    let candidate = "https://example.test/?token=raw-token";
    let acceptable = Redactor::strict()
        .inspect_uri(candidate)
        .is_ok_and(|inspection| !inspection.contains_sensitive());
    assert!(!acceptable);
}
```

### 处理 argv、环境变量和进程诊断

调用方知道参数契约时，应优先显式标记 argv。启发式 argv 能识别受支持的 option 形式，但不是
shell parser：

<!-- redact-example: kind=run features=none -->
```rust
use std::ffi::OsStr;

use qubit_redact::{Redactor, Sensitivity};
use qubit_redact::formats::argv::ArgvItem;

fn main() {
    let arguments = [
        ArgvItem::plain(OsStr::new("--server=example.test")),
        ArgvItem::sensitive(OsStr::new("raw-token"), Sensitivity::Secret),
    ];
    let variables = [(OsStr::new("PASSWORD"), OsStr::new("raw-password"))];
    let output = Redactor::standard().redact_process(OsStr::new("client"), arguments, variables);
    assert!(!output.text().as_str().contains("raw-"));
}
```

### Feature 选择

| Feature | 提供的能力 |
| --- | --- |
| `derive` | `#[derive(Redact)]`, `#[derive(RedactScalar)]` |
| `serde` | derive/domain 的结构化 Serde 适配器 |
| `bigdecimal` | BigDecimal 标量与等级支持，同时启用 `serde` |
| `json` | JSON 文本及借用的 `serde_json::Value` |
| `http` | JSON、URL、header、form、multipart 和 body capture |
| `uri` | 通用 URI 解析与脱敏 |

只使用标量和手写领域实现时可保持默认空 feature 集。在 0.8 版本系列中，`serde` 提供结构化
序列化，BigDecimal 支持则通过 `bigdecimal` feature 显式启用。

## 标准策略与 strict 策略

`Redactor::standard()` 使用内置字段表；未识别的标量字段名保持可见。适合领域类型已声明
敏感度、或未知键本身就需要出现在诊断里的场景。

`Redactor::strict()` 把未识别的标量字段当作 secret。适合不可信的键值映射、用户提供的
查询参数，或字段名不受你控制的第三方 JSON。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;

fn main() {
    let field = "custom_metric";
    let value = "visible-value";
    assert!(
        !Redactor::standard()
            .redact_field(field, value)
            .text()
            .as_str()
            .contains("<redacted>")
    );
    assert_eq!(
        Redactor::strict().redact_field(field, value).text().as_str(),
        "<redacted>"
    );
}
```

strict 不会降低 derive 显式等级或手写 `sensitive_at_least` 的域类型声明；它作用于
`redact_field`、JSON key、HTTP query 等运行时分类路径。

## 进阶用法

### 检查决策与控制策略

检查 API 会报告规则匹配、敏感度和完成状态，但不会发布原始值。它适合在确定日志或序列化
边界前解释某字段为何会被掩码。

inspection 不会调用字段的 `Debug`、`Display` 或 `Serialize`。即使格式化路径配置错误会在
渲染时 panic，inspection 仍可完成，因此适合不能泄露任何字节的安全门禁。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

fn main() {
    let inspection = Redactor::standard()
        .inspect_field("password", "raw-secret")
        .expect("field inspection should complete");
    assert!(inspection.contains_sensitive());
    assert_eq!(inspection.max_sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(inspection.usage().output_bytes(), 0);
}
```

领域对象、JSON 文本与值、HTTP 各部分、URI、argv、环境变量对以及完整进程描述都有对应的
`inspect_*` 入口。若 inspection 结果用于准入决策，任何错误都应视为分类不完整。

建议构造一份不可变策略，再共享生成的 `Redactor`。builder closure 具有事务语义：字段规则
无效时，原 builder 不会受到部分修改。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("session_id", Sensitivity::High);
        })
        .expect("valid field rule")
        .limits(|limits| {
            limits.max_input_bytes(64 * 1024);
            limits.max_output_bytes(8 * 1024);
            limits.max_collection_items(256);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    assert!(!redactor.redact_field("session_id", "raw-session").text().as_str().contains("raw-session"));
}
```

### 字段规则、floor 与 allow

运行时字段规则补充 derive 标注，不会把显式 derive 等级降低。常见 builder 调用包括：

| Builder 调用 | 作用 |
| --- | --- |
| `secret_sensitive(name)` | 将精确字段名分类为 secret |
| `raise(name, level)` | 把运行时分类至少提升到给定等级 |
| `allow_exact` / `allow_suffix` | 允许列出的名称保持未分类 |
| `floor(floor)` | 为匹配名称安装最低脱敏 floor |

当 floor 与 allow 规则同时匹配同名字段时，floor 可以把敏感度提高到 allow 之上。floor 适合
供应商 token 等绝不能原样出现的字段，即使 allow 列表本来会放行该名称。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionFloor, RedactionPolicy, Redactor, Sensitivity};

fn main() {
    let floor = RedactionFloor::builder()
        .raise("access_token", Sensitivity::High)
        .expect("valid floor rule")
        .build()
        .expect("valid floor");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor).allow_exact("access_token");
        })
        .expect("valid field rule")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_field("access_token", "raw-token");
    assert_eq!(output.text().as_str(), "****");
}
```

`RedactionPolicy::disabled()` 是显式关闭保密脱敏的选项，也是框架有意保留的进程级调试
逃生口。字段、JSON、URI、HTTP、环境变量、argv、进程、derive 字段模式和生成的 Serde
输出都会恢复原值，但仍受运行时资源上限约束。控制字符转义也仍然生效，但这两项机制都不
表示结果已经脱敏。框架只负责执行所选策略；是否有权禁用、在哪个环境和时机禁用，以及误用
后果都由下游负责。让不可信请求控制该开关通常是不安全的，但阻止下游故意或错误调用 API
不属于框架保证。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionPolicy, Redactor};

fn main() {
    let mut policy = RedactionPolicy::disabled();
    assert!(policy.is_disabled());
    policy.set_disabled(false);
    let output = Redactor::new(policy).redact_field("password", "raw-secret");
    assert!(!output.summary().is_redaction_disabled());
    assert!(!output.text().as_str().contains("raw-secret"));
}
```

策略启用时，`Complete`、`Truncated` 和 `Exhausted` 文本都应保持保密安全。只有调用方
关心完整性、审计原因或重试决策时才检查 `summary().completion()` 与
`summary().reasons()`，不要解析 `<truncated>` 等文本标记推断状态。若 inspection 用于
安全决策，任何检查错误都表示分类不完整，应按敏感处理。

`Redactor::replace_application_default()` 影响之后调用 `application_default()` 取得的对象，
以及每次重新获取快照的生成格式化代码。已经创建的 `Redactor`、文本组合器和批处理对象继续
持有原有不可变快照；替换不会追溯切换正在进行的工作。

## 预算计量与 0.8 迁移

| 入口 | 结构与输入限制 | Serde 逻辑载荷 | 最终编码字节 |
| --- | --- | --- | --- |
| 字段、领域文本、composer、batch | 各入口共享事务准入 | 不适用 | `max_output_bytes` |
| view 或派生源对象的 `Serialize` | 共享 Serde scope | `max_serde_payload_bytes` | 调用方 writer 控制 |
| `to_json` | 共享 Serde scope | `max_serde_payload_bytes` | `max_output_bytes` |
| `redact_json` / `redact_json_value` | 文本事务与 JSON 专有限制 | 不适用 | `max_output_bytes` |

`max_input_bytes` 默认 64 KiB；两个输出相关限制各默认 16 KiB。它们均允许 0。
Serde 载荷与最终输出限制超过 `isize::MAX` 时策略构造报错。
升级到 0.8 时，将旧的 `batch()` 调用改为 `diagnostic_batch()`。默认诊断标记使用
`finish()`，自定义标记使用 `finish_with_marker(marker)`。使用 BigDecimal 时需显式启用
`bigdecimal`，仅启用 `serde` 已不再提供该能力。

0.6 中用于限制直接 Serde 载荷的 `max_output_bytes` 配置须迁移到
`max_serde_payload_bytes`；需要同时限制 `to_json` 时设置两个值，二者不会自动联动。

字段入口先检查根节点、key 长度，再准入字段名 UTF-8 字节，随后才分类和格式化值。
脱敏启用时，High/Secret 只计字段名字节，不调用值的 Display。capture 按完整写入片段准入：拒绝片段
计入 presented，不计入 inspected；已接受片段仍计费，失败时其原文全部丢弃。
因此 `inspected_input_bytes <= max_input_bytes`，但 presented 可以更大。
领域字段的静态标签、结构节点以及 Serde 事件有各自准入单位，不能把它们的 usage 当作原对象大小。

Serde 逻辑载荷按 str/char 的 UTF-8 字节、bytes 切片长度及数字/bool 的标量表示计量；
none/unit 为 0，动态 map key 和标量形式的 unit variant 名称计入载荷。
静态字段名、标点、转义和编码 framing 不计入此额度。
嵌套事件共享账本，普通 Serialize 仅执行一次。`to_json` 的最终额度则包含所有 JSON 标签、
引号、转义、标点和掩码。比如 `{"value":"abcd"}` 的逻辑载荷是 4 字节，最终 JSON 是 16 字节。
任意第三方 serializer 的额外编码开销必须由调用方限制。

| 标量结果 | completion | reasons | 允许后项继续 |
| --- | --- | --- | --- |
| 正常文本或固定掩码完整容纳 | Complete | 无降级原因 | 是，除非额度恰好用尽 |
| 输入拒绝，替代可容纳 | Truncated | InputLimitReached | 是，仍需逐项准入 |
| formatter 自身返回 Err，替代可容纳 | Truncated | FormattingFailed | 是 |
| 上述替代不能容纳 | Exhausted | 原因 + OutputLimitReached | 否 |
| 输出真实截断，替代可容纳 | Truncated | OutputLimitReached | 否 |
| 输出连替代也不能容纳 | Exhausted | OutputLimitReached | 否 |

单项失败不会重置批次预算，也不会无条件关闭输出；aggregate summary 保留不完整状态。
`finish_with_marker(marker)`、`text_or_marker` 等发布后的展示替代会转义 marker，
但 marker 及调用方日志前后缀不计入原事务 `output_bytes` 或 `max_output_bytes`。
预算约束库可控制的准入和写入，不抢占 Display/Serialize 内部的任意计算或调用前的分配。

## 错误与诊断

当调用方需要区分完整结果与预算或解析降级时，检查 `summary().completion()`、
`summary().reasons()` 和 `summary().usage()`；不要解析展示文本来推断状态。严格的展示路径可用
`complete_text()` 和 `into_complete_text()` 拒绝不完整结果；诊断展示可用 `text_or_marker()` 和
`into_text_or_marker()` 选择明确的降级标记。若检查结果用于安全判断，任何检查错误都意味着
分类不完整，应按敏感结果处理。

## 处理不完整结果

`RedactionCompletion` 区分完整渲染与预算或解析降级。诊断场景通常直接记录 `text()` 或
`text_or_marker(fallback)`，事后再看 `summary().reasons()`。审计或存储路径若要求完整性，
应调用 `complete_text()` / `into_complete_text()` 并显式处理错误。

<!-- redact-example: kind=run features=none -->
```rust
use qubit_redact::{RedactionCompletion, RedactionPolicy, Redactor};

fn main() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_field("password", "raw-secret");
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.text_or_marker("<truncated>"), "<truncated>");
    assert!(output.complete_text().is_err());
}
```

即使 `completion()` 不是 `Complete`，已发布文本仍保持保密安全：库输出掩码或调用方指定的
marker，而不是半截 secret。传给 `text_or_marker` 或 `finish_with_marker` 的 marker 会被转义，
且不计入原事务的 `output_bytes`。

## 排障

| 现象 | 优先检查 | 说明 |
| --- | --- | --- |
| 输出出现原值 | `summary().is_redaction_disabled()` 与 `Redactor` 快照 | disabled 策略会按设计恢复原值 |
| standard 下未知字段仍可见 | 改用 `Redactor::strict()` 或添加字段规则 | standard 有意保留未列出名称 |
| strict 下未知字段被过度掩码 | 添加 `allow_exact` / `allow_suffix` 或改用 standard | strict 默认把未知标量当 secret |
| batch 某项被截断或为空 | `completion()`、`reasons()`、`usage()` | 较早的 batch 项会消耗共享额度 |
| 句柄显示降级 marker | 句柄是否属于当前 batch | 句柄不能跨 batch 使用 |
| `complete_text()` 失败 | 输出被截断或耗尽 | 审计路径的预期行为；日志可用 `text_or_marker` |
| 领域字段未命中 | derive 等级、keyed_by 兄弟字段、手写 `Redact` | 运行时不会从 Rust 类型推断业务语义 |
| JSON key 仍可见 | 使用的是 `redact_json_value` 还是领域 `Redact` | JSON 文本路径按 key 分类；领域路径看标注 |
| 测试里 inspection 不 panic 但日志泄露 | 生产日志是否绕开脱敏入口 | inspection 本身不渲染值 |
| URI 该拒绝却被接受 | 是否只用了 `redact_uri` 而非 `inspect_uri` | 脱敏产出安全文本；准入应走 inspection |
| HTTP body 显示来源截断 | `RedactionReason::SourceTruncated` 与输出限制 | 不完整 body 应使用对应的 `BodyCapture` 构造方式 |

## 并发与运行时约束

每个 `Redactor` 持有不可变的 `Arc<RedactionPolicy>` 快照。克隆 redactor 开销低且线程安全。
composer、batch 和 inspection 会话默认不应跨线程共享；每个诊断事件各建一份会话。

`Redactor::replace_application_default()` 只影响之后通过 `application_default()` 取得的快照，
以及会重新读取全局默认值的生成格式化代码。已创建的 redactor、composer 和 batch 仍保留
创建时的策略。

库不擦除源内存，不拦截任意 `println!` 或 tracing 宏，也不限制 redaction 开始前用户在
`Display` / `Serialize` 内部执行的计算。若最终编码大小需要与 Serde 逻辑载荷分开限制，
请在外部 serializer 侧额外设限。

## 限制与最佳实践

- 应依据业务领域知识标记敏感字段；`unmarked` 和未标注的 derive 字段会有意保持可见。
- 不要将 `RedactionPolicy::disabled()` 暴露给请求控制的输入；它会恢复原值，只适合作为进程级
  调试逃生口。
- 本 crate 只保护经过其运行时的调用，不擦除源对象内存，也不保护无关日志或序列化路径。

## 延伸阅读

- [中文 README](../README.zh_CN.md) · [English README](../README.md)
- [0.8 API 文档](https://docs.rs/qubit-redact/0.8/qubit_redact/)
- [derive 说明](../derive/README.zh_CN.md) · [英文用户手册](user_guide.md)
- [设计文档](design.zh_CN.md) · [English design](design.md)

在仓库根目录运行 `python3 -B scripts/check_doc_examples.py`，可以编译并执行两种语言的 README
与用户手册中所有带注解的 Rust/Cargo 代码块。校验脚本以本仓库为 path 依赖，在临时 consumer
crate 中离线运行；依赖需已缓存。

验证本地检出与完整 CI 矩阵：

```bash
./align-ci.sh
./ci-check.sh
```

`ci-check.sh` 读取仓库内的 `.rs-ci-cargo-matrix.json`，执行 `check`、`test`（含 doctest）、
`doc` 和 Clippy。矩阵覆盖最小格式 feature、derive 与 Serde/JSON/HTTP/URI 的消费组合、
显式 BigDecimal 支持，以及全部 feature：展开隐式依赖后覆盖全部 28 种 runtime feature 集，
另检查 derive crate。README 与指南示例按实际依赖验证；未启用 `uri`
时，只跳过需要它的 URI 示例。

# Qubit Redact 用户手册

[README](../README.zh_CN.md) · [English User Guide](user_guide.md) · [Runtime API](https://docs.rs/qubit-redact) · [derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.zh_CN.md) · [derive 用户手册](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)

Qubit Redact 是一个策略驱动的 Rust 脱敏库，用于防止敏感值经诊断信息泄露：
结构化字段和 Map、领域对象、进程参数、环境变量，以及可选的 HTTP 数据都在其覆盖范围内。

## 目录

- [安装与示例运行方式](#安装与示例运行方式)
- [配置策略](#1-用-redactionpolicy-配置规则)
- [标量、Map 与日志文本](#2-用-redactor-处理标量和-map)
- [领域对象](#4-用-redact-和-redactmut-处理领域对象)
- [进程诊断](#5-用-argvredactor-处理命令行参数)
- [HTTP 诊断](#7-用-httpredactor-处理-http-诊断)
- [URI 诊断](#8-用-uriredactor-处理-uri-诊断)
- [安全边界与排查](#安全边界与验证)

## 它解决什么问题

秘密通常不是从认证代码泄露，而是从错误日志、调试输出和序列化诊断对象泄露。
在每个日志调用点做字符串替换容易遗漏，也难以审查。Qubit Redact 用不可变
`RedactionPolicy` 集中定义“什么可以展示、什么必须遮盖”。

下面的完整程序保留原始秘密，同时遮盖诊断值。

```toml
[dependencies]
qubit-redact = "0.5"
```

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::builder();
    builder.fields().raise("user_id", Sensitivity::Low)?;
    builder.fields().raise("phone_number", Sensitivity::Medium)?;
    builder.fields().raise("credit_card", Sensitivity::High)?;
    builder.fields().raise("api_key", Sensitivity::Secret)?;
    let policy = builder.build()?;
    let redactor = Redactor::new(policy);
    let user_id = "alpine42";
    let phone_number = "13800138000";
    let credit_card = "4111111111111111";
    let api_key = "sk_live_123";
    let display_name = "Alice\nAdmin";

    assert_eq!(redactor.redact_field("user_id", user_id).as_str(), "al****42");
    assert_eq!(redactor.redact_field("phone_number", phone_number).as_str(), "*******0");
    assert_eq!(redactor.redact_field("credit_card", credit_card).as_str(), "****");
    assert_eq!(redactor.redact_field("api_key", api_key).as_str(), "<redacted>");
    assert_eq!(redactor.redact_field("display_name", display_name).as_str(), display_name);
    assert_eq!(api_key, "sk_live_123");
    assert_eq!(
        redactor
            .redact_field("display_name", display_name)
            .escape_for_log()
            .to_string(),
        "Alice\\nAdmin",
    );
    Ok(())
}
```

## 如何选择工具

| 诊断输入 | 首选工具 | 返回结果与日志边界 |
| --- | --- | --- |
| 具名标量值 | `Redactor::redact_field` | `RedactedText`；写入纯文本日志前转为 `LogSafeText` |
| 文本 key Map | `Redactor::redact_map` 或 `redact_map_in_place` | 返回副本或修改原 Map；显式选择最终日志格式 |
| Rust struct 或 enum | `Redact` derive | `Redacted<T>` 视图 |
| 需要逻辑替换的值 | `Redact` derive | 使用同一 derive 生成的 `RedactMut` 修改对象；不等于内存擦除 |
| 命令行参数 | `Redactor::session().argv()` | `RedactedArgv` |
| 环境变量 pair | `Redactor::session().env()` | `RedactedEnvPair` 或 `LogSafeText` |
| URL、form、Header、捕获的 body | `Redactor::session().http()` | 日志安全 HTTP 结果类型 |
| URI 字符串 | `Redactor::session().uri()` | 带组件原因的结构化日志安全结果 |

## 安装与示例运行方式

包名是 `qubit-redact`，Rust 导入路径是 `qubit_redact`。默认 feature 没有运行时
依赖；领域对象使用 derive crate，脱敏序列化启用 `serde`，HTTP 诊断启用 `http`。
本手册每个 Rust 代码块都是完整的 `main.rs`：使用该节给出的依赖并运行 `cargo run`。

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["serde", "http"] }
qubit-redact-derive = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
http = "1.5"
```

## 核心概念

`RedactionPolicy` 是一份不可变快照，统一包含基础字段规则、HTTP/URI 上下文覆盖、可选最低
`RedactionFloor`、匹配方式、一套掩码表和静态限制；启用 `json` feature 时还包含
`JsonDepthLimit`。`http()` 和 `uri()` 视图只保存相对于基础规则的上下文差异。
`classify_field()` 只解释应用层为何得到 **Sensitive**（遮盖）、显式例外的
**Allowed**（允许展示）或 **Unknown**；最终安全裁决由 `sensitivity_for()` 和脱敏 API 完成，
它们会合并应用层和 floor。`UnknownFieldPolicy` 默认是 `PassThrough`；边界必须遮盖未分类字段时设置
`Redact(Sensitivity::Secret)`，而 `classify_field()` 仍报告 `Unknown`。
`RedactionPolicy::strict()` 提供这一边界预设，但不会改变默认策略语义。
`Redactor` 始终使用同一份快照。

`RedactedText` 只表示“已按字段规则处理”，它故意不实现 `Display`。写入纯文本日志前，
必须调用 `escape_for_log()` 得到可安全显示的 `LogSafeText`。

领域对象或 Map 视图的 `Debug` 与日志安全 `Display` 默认都使用策略诊断输出预算；
需要不同的显式限制时调用 `with_output_limit()`。派生的嵌套对象、Map、JSON 文本
和适配器会共享一个不可克隆的 `RedactionSession`，不会通过嵌套调用重置父级预算。

`InputOutputLimit` 是存储在策略中的不可变限制；运行时由一个 `RedactionSession`
记录一次诊断事件，并由嵌套 adapter 共享。adapter 会在检查输入前先完成 admission，并原子
提交自己的输出（包括 fallback 标记），因此 eager 片段不能超过累计输出预算。

| API | 初始状态 | 适用场景 |
| --- | --- | --- |
| `RedactionPolicy::default()` | 已安装的进程级快照，或固定标准策略 | 接受应用当前的默认策略。 |
| `RedactionPolicy::builder()` | 空应用规则加标准 floor | 需要由当前调用点定义应用规则且保留 floor。 |
| `RedactionPolicy::default().to_builder()` | 当前默认快照的副本 | 需要在标准默认策略上扩展。 |
| `RedactionPolicy::install_global()` | 每个进程只能安装一次 | 应用初始化代码拥有默认策略快照。 |

可用 `include_preset(SensitiveFieldPreset::...)` 向显式策略加入内置的凭据、凭据容器、
认证令牌、HTTP 或会话字段组。策略测试或诊断需要解释决策时，使用
`classify_field()` 获取 `Sensitive`、`Allowed` 或 `Unknown`。

## 1. 用 `RedactionPolicy` 配置规则

`RedactionPolicy::builder()` 从空应用敏感/allow 规则和标准 floor 开始。
`RedactionPolicy::default()` 读取已安装的进程级默认快照；尚未安装时读取固定标准策略。扩展该快照时使用
`RedactionPolicy::default().to_builder()`。只有调用方明确承担取消最低保护的风险时才可
使用 `disable_floor()`；应用层 allow 规则无法绕过启用的 floor。Builder 不会隐式读取全局状态。
`raise` 不会降低既有等级；需要有意替换时使用
`override_level`。
精确允许规则范围窄；后缀允许规则可能放行带前缀字段，需安全审查。

```rust
use qubit_redact::{
    FieldNameMatching, MaskPolicy, RedactionPolicy, Redactor, Sensitivity,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .raise("tenant_reference", Sensitivity::High)?
        .raise("tenant_visible", Sensitivity::High)?
        .allow_exact("tenant_visible")?
        .mask(Sensitivity::High, MaskPolicy::fixed("[hidden]"))?;
    let policy = builder.build()?;
    let redactor = Redactor::new(policy);

    assert_eq!(redactor.redact_field("TENANT_REFERENCE", "abc").as_str(), "[hidden]");
    assert_eq!(redactor.redact_field("tenant_visible", "visible").as_str(), "visible");
    Ok(())
}
```

全局策略只应在应用初始化时安装：

```rust
use qubit_redact::{RedactionPolicy, Sensitivity};

let mut builder = RedactionPolicy::builder();
builder.fields().raise("api_key", Sensitivity::Secret)?;
let policy = builder.build()?;
RedactionPolicy::install_global(policy)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

每个进程只能成功安装一次。安装前读取 `global()` 或 `default()` 只会取得固定标准策略，
不会阻止后续安装。测试或多个安全边界应传递显式策略快照。

字段名会被规范化。使用 `FieldNameMatching::ExactOrTokenSuffix` 时，`api_key` 规则可
匹配 `request_api_key`；精确匹配范围最窄。

`raise(field, level)` 有两层“只升不降”语义：同一规范键被多次配置时保留最高等级；一个
输入同时命中多个不同规则时，最终也取所有命中规则的最高等级。例如 `token = Secret`、
`access_token = Medium` 都会匹配 `OPENAI_ACCESS_TOKEN`，最终结果是 `Secret`，不会因
更长的 `access_token` 规则降为 `Medium`。`override_level("access_token", Medium)` 只
替换 `access_token` 这一条规则，不能绕过仍然命中的 `token = Secret`。它适合明确修正
同一规则的配置值，不是降低重叠规则整体保护等级的工具。

allow 判定与 sensitive 等级归并是两件事：精确 allow 规则只影响一个规范字段；后缀
allow 规则可能放行带前缀字段，必须经过安全审查。未被 allow 放行时，才对全部匹配的
sensitive 规则取最高等级；启用的 floor 仍独立生效。

当边界已知某值敏感而与字段名无关时，使用 `Redactor::redact_at(level, value)`。它直接
应用指定掩码，因此 allow 规则不能暴露该值。

## 2. 用 `Redactor` 处理标量和 Map

`redact_field(field, value)` 是基本操作，返回能区分已遮盖、允许展示和未知直通的
`FieldRedaction`。`redact_map` 返回保持原集合类型的副本，
`redact_map_in_place` 原地替换敏感值。支持文本 key 的 `HashMap`、`BTreeMap` 和
`indexmap::IndexMap`。

它只根据 `field` 分类，不会扫描 `value` 的内容。例如
`redact_field("error", "request failed: password=raw-secret")` 中，如果 `error` 没有
敏感规则，整段 value 会原样通过；库不会从字符串里自动识别 `password=`。已解析数据应
拆成 `redact_field("password", password)` 等结构化字段。来源不可信的完整错误文本应
使用固定安全摘要并把原错误保留在 `Error::source()`，或者在确实需要输出一个不透明值时
使用 `redact_at(Sensitivity::Secret, text)`。

```rust
use std::collections::HashMap;
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .raise("user_id", Sensitivity::Low)?
        .raise("phone_number", Sensitivity::Medium)?
        .raise("credit_card", Sensitivity::High)?
        .raise("api_key", Sensitivity::Secret)?;
    let policy = builder.build()?;
    let source = HashMap::from([
        ("user_id".to_owned(), "alpine42".to_owned()),
        ("phone_number".to_owned(), "13800138000".to_owned()),
        ("credit_card".to_owned(), "4111111111111111".to_owned()),
        ("api_key".to_owned(), "sk_live_123".to_owned()),
        ("display_name".to_owned(), "Alice".to_owned()),
    ]);

    let copy = Redactor::new(policy).redact_map(&source);
    assert_eq!(copy["user_id"], "al****42");
    assert_eq!(copy["phone_number"], "*******0");
    assert_eq!(copy["credit_card"], "****");
    assert_eq!(copy["api_key"], "<redacted>");
    assert_eq!(copy["display_name"], "Alice");
    assert_eq!(source["api_key"], "sk_live_123");
    Ok(())
}
```

不要将 `serde_json::Map<String, serde_json::Value>` 这类异构领域对象当作普通字符串
Map；应通过领域类型定义明确的替换语义。

`redact_map` 返回原集合类型，`redact_map_in_place` 原地修改该集合。两者都不会将 Map
变成 `LogSafeText`；最终写日志时仍应选择合适的格式化方式。

启用 `json` feature 后，`RedactedJson`、`RedactedJsonText` 和
`redact_json_text_in_place` 都使用不可变策略中的 `JsonDepthLimit`。根节点深度为 0；
下一个 object 或 array 到达配置上限时，整个子树会在不访问后代的情况下替换成策略的
Secret 不透明掩码。默认最大深度为 128；需要更小的正数限制时，使用
`RedactionPolicyBuilder::limits().json_depth(...)` 配置。

JSON 文本可以通过 `session.json()` 与其他 adapter 共享同一个事件预算：

```rust
use qubit_redact::Redactor;

let redactor = Redactor::strict();
let mut session = redactor.session();
let safe = session.json().redact_text(r#"{"token":"raw-token"}"#);
assert!(!safe.to_string().contains("raw-token"));
```

## 3. 将脱敏文本安全写入日志

脱敏与日志安全是两层保证：即使字段允许展示，换行符或 Unicode 控制字符仍可改变日志
结构。`escape_for_log()` 返回实现 `Display` 的 `LogSafeText`。`LogOutputLimit` 对最终
输出施加字节上限，并以 `<truncated>` 截断，且不会切断 UTF-8 或转义序列。

```rust
use qubit_redact::{LogOutputLimit, Redactor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let safe = Redactor::default()
        .redact_field("message", "first line\nsecond line")
        .escape_for_log();
    assert_eq!(safe.to_string(), "first line\\nsecond line");

    let limit = LogOutputLimit::new(16)?;
    let bounded = safe.with_output_limit(limit).to_string();
    assert!(bounded.len() <= limit.max_bytes());
    Ok(())
}
```

在自定义 `Debug` 实现中，如捕获值必须固定显示为 `<redacted>`，请使用
`redacted_debug(value)`；它不会调用被包装值自己的 `Debug` 实现。

## 4. 用 `Redact` 处理领域对象

`qubit-redact-derive` 提供 `Redact` 过程派生宏，将运行时策略应用到 Rust struct 和
enum。它为诊断信息创建借用视图，并默认生成 `RedactMut`，需要拥有式值时可以显式替换
逻辑值。
在字段边界，`level` 遮盖字段，`plain` 记录有意直通，`nested` 递归，`map` 按 key
处理 Map 值，`skip` 从脱敏表示中省略字段。需要每个字段都显式选择模式时，添加
`#[redact(require_explicit)]`；默认语义保持不变。完整的宏参考和示例请参阅
[derive README](https://github.com/qubit-ltd/rs-redact-derive/blob/main/README.zh_CN.md) 和
[derive 用户手册](https://github.com/qubit-ltd/rs-redact-derive/blob/main/doc/user_guide.zh_CN.md)。

```toml
[dependencies]
qubit-redact = "0.5"
qubit-redact-derive = "0.5"
```

```ignore
use qubit_redact::domain::{Redact as _, RedactMut as _};
use qubit_redact_derive::Redact;

#[derive(Clone, Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() {
    let credentials = Credentials {
        user: "ada".to_owned(),
        password: "raw-password".to_owned(),
        internal_note: "not logged".to_owned(),
    };
    assert!(!format!("{:?}", credentials.redacted()).contains("raw-password"));

    let mut mutable = credentials.clone();
    mutable.redact_in_place();
    assert_eq!(mutable.password, "<redacted>");
    assert_eq!(mutable.internal_note, "not logged");
}
```

`RedactMut` 仅做逻辑替换，不会擦除已释放的内存、别名、副本或借用后备存储；需要内存
擦除时请使用专门的 zeroization 方案。

普通字段绝不会被隐式遍历。derive 支持具名、tuple、unit struct 以及具有这些 variant
形态的 enum。

### 使用 Serde 序列化领域对象或脱敏视图

序列化必须显式 opt-in：启用 `serde` feature，在使用方直接声明 `serde`，并添加
`#[redact(serde)]`。原类型直接序列化时会自动脱敏；`Redacted` 仍支持策略感知的
序列化，但不实现 `Deserialize`。

若 `String` 存储 JSON，启用 `json` feature 并使用 `#[redact(json)]`。它按 JSON
对象 key 递归应用策略，`Redact` 格式化脱敏视图，`RedactMut` 改写为紧凑脱敏 JSON；
解析失败时安全关闭为不透明掩码。Serde 仍将字段序列化为 JSON 字符串，而非嵌入解析后的对象。

`#[redact(debug)]` 和 `#[redact(display)]` 让原类型通过进程级默认策略进行安全格式化。
不要将它们与同一 trait 的已有实现组合使用。

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["serde"] }
qubit-redact-derive = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```ignore
use qubit_redact::domain::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct LoginEvent {
    account: String,
    #[redact(level = "secret")]
    token: String,
    #[redact(skip)]
    internal_note: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event = LoginEvent {
        account: "ada".to_owned(),
        token: "raw-token".to_owned(),
        internal_note: "operator-only".to_owned(),
    };
    let json = serde_json::to_string(&event)?;
    assert!(!json.contains("raw-token"));
    assert!(!json.contains("operator-only"));
    Ok(())
}
```

直接序列化使用进程级默认策略；需要显式策略快照时，序列化
`event.redacted_with(&policy)`。`#[redact(serde)]` 生成 `Serialize`，不生成
`Deserialize`。

## 5. 使用共享 `RedactionSession` 处理命令行参数

`redact_items` 信任 `ArgvItem` 提供的敏感等级；`redact_heuristically` 还识别
`--password value`、`--password=value`、`-password value`、`NAME=value` 和
`-Dpassword=value`。它不会推断紧凑的 `-pSECRET` 或 shell payload，必须显式标记。

```rust
use std::ffi::OsStr;
use qubit_redact::argv::ArgvItem;
use qubit_redact::{Redactor, Sensitivity};

fn main() {
    let items = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("raw-password")),
        ArgvItem::sensitive(OsStr::new("raw-api-key"), Sensitivity::Secret),
    ];
    let redactor = Redactor::default();
    let mut session = redactor.session();
    let output = session.argv().redact_heuristically(items).to_string();
    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-api-key"));
}
```

返回的 `RedactedArgv` 可安全显示；输入和输出受策略中的 `InputOutputLimit` 限制。

渲染参数集合时，即使共享输入预算在读取第一个元素前就已耗尽，也会保留集合外框；此时安全结果
可能是 `['<truncated>']`。

## 6. 使用共享 `RedactionSession` 处理环境变量

`EnvRedactor` 通过变量名分类其值，返回日志安全的 `NAME=VALUE`。`redact_os_pair`
接受 `OsStr`，遇到非 UTF-8 输入会安全关闭并使用不透明掩码。

```rust
use qubit_redact::Redactor;

fn main() {
    let redactor = Redactor::default();
    let mut session = redactor.session();
    let password = session.env().redact_pair("PASSWORD", "raw-password");
    let assignment = session.env().redact_pair("API_TOKEN", "raw-token");

    assert_eq!(password.to_string(), "PASSWORD=<redacted>");
    assert!(!assignment.to_string().contains("raw-token"));
}
```

渲染进程变量列表时使用 `redact_os_pairs`：它在整个列表中共享输入预算，超出时用截断
标记停止，而不会继续读取原始数据。

## 7. 使用 `session.http()` 处理 HTTP 诊断

可选 `http` feature 提供统一的不可变 `RedactionPolicy`，分别处理 Header、query/form 和
结构化 body。它的 `http()` 视图只保存 HTTP 上下文差异；基础字段规则、掩码和限制仍位于
同一份策略中。`RedactionPolicy::builder()` 不带应用字段规则并使用标准 floor。应用层
allow 规则无法绕过已启用的 floor。要在标准快照上扩展，使用
`RedactionPolicy::default().to_builder()`。Builder 不会隐式读取全局状态。
`RedactionPolicy::default()` 和 `HttpRedactor::default()` 的标准策略保留
URL path 以便诊断；当 URL path 可能包含敏感标识符时，请使用
`RedactionPolicy::strict()` 或显式设置 `UrlPathPolicy::Redact`。

`HttpRedactor` 应用该快照。`BodyCapture` 提供借用字节和真实完整性元数据（`complete`、
`prefix` 或截断 capture），因此库不会读取网络流。`BodyBudget` 限制检查和渲染的 body
字节；`InputOutputLimit` 单独限制 URL、form、header 和含 URL 的文本；
`JsonDepthLimit` 限制 JSON 和 NDJSON 的递归深度。`BodyRedaction`
是有界日志安全结果；`BodyRedactionStatus` 说明其为结构化成功、策略放行、安全关闭、
二进制或空结果，`BodyRedactionReason` 则解释安全关闭的原因。所有结果都不提供原始 body
逃生接口。

| 输入 | 默认安全行为 | 使用的配置 |
| --- | --- | --- |
| URL query、用户名、密码、fragment | 遮盖已配置字段和敏感 URL 组成部分 | `builder.http().query().raise(...)`、`builder.uri()`、`UrlPathPolicy` |
| form 与 Header | 遮盖已配置字段，且输出有界 | `builder.http().header()`、`builder.http().query()` |
| JSON、NDJSON、form body、multipart | 解析完整输入；不安全、超深或截断时失败时默认遮盖 | `builder.http().body()`、`builder.limits()`、`JsonDepthLimit` |
| 不透明文本、无 key JSON | 默认采取保守策略 | 仅在接受风险后显式使用 `PassThrough` |
| URL path | 标准策略保留，strict 策略脱敏 | `UrlPathPolicy::Redact` 或 `RedactionPolicy::strict()` |
| 非 UTF-8 body | 返回二进制摘要，绝不暴露原始字节 | `BodyRedactionStatus::Binary` |

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["http"] }
http = "1.5"
```

```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};
use qubit_redact::http::BodyCapture;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = RedactionPolicy::default().to_builder();
    builder.http().body().raise("password", Sensitivity::Secret)?;
    builder.http().query().raise("api_key", Sensitivity::Secret)?;
    let policy = builder.build()?;
    let redactor = Redactor::new(policy);

    let mut session = redactor.session();
    let url = session.http().redact_url_str(
        "https://api.example.test/login?api_key=raw-key&mode=debug",
    );
    assert!(!url.to_string().contains("raw-key"));

    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-token"));
    assert!(!session
        .http()
        .redact_headers(&headers)
        .to_string()
        .contains("raw-token"));

    let content_type = HeaderValue::from_static("application/json");
    let body = session.http().redact_body(
        BodyCapture::complete(br#"{"password":"raw-password","mode":"debug"}"#),
        Some(&content_type),
    );
    assert!(matches!(body.status(), qubit_redact::http::BodyRedactionStatus::Structured));
    assert!(!body.to_string().contains("raw-password"));
    Ok(())
}
```

一个 `RedactionPolicyBuilder` 通过 `http().header()`、`http().query()` 和
`http().body()` 提供上下文规则、floor、敏感度和 allow-list 配置；共享的静态限制通过
`limits()` 配置。无效或截断的结构化输入会安全关闭。

运行时诊断可读取 `BodyRedaction::status()`、`is_truncated()`、`captured_len()` 和
`omitted_len()`。`BodyRedactionStatus::Redacted(reason)` 会给出结构化或可见表示不安全的原因。

## 8. 使用 `session.uri()` 处理 URI 诊断

可选 `uri` feature 提供基于解析器的 URI facade，且不会隐式启用 `http`：

```toml
qubit-redact = { version = "0.5", features = ["uri"] }
```

`UriRedactor` 保留可见组件的原始 scheme、host、port、path、query 顺序和百分号编码。
userinfo 只在第一个原始、未编码的 `:` 处分割：用户名按 `username` 字段分类，密码按
`password` 字段分类。标准策略下只有用户名的 authority 默认可见，也可以通过同一套核心
策略规则允许或遮盖。

query 的 key 和 value 会严格解码后再做策略判断；`+` 保持为字面加号，第一个 `=` 才是
pair 分隔符，未遮盖的值保留原始编码，已遮盖的值重新做 URI 编码。path 默认保留，fragment
默认遮盖，两者都可通过 `RedactionPolicyBuilder` 配置。语法无效、query UTF-8 无法解码
或输入超预算时返回 `<invalid URI>`，不会保留原始 URI 文本。

`UriRedaction` 提供日志安全文本、状态、已变更组件、原因和输出截断元数据；其 `Debug` 和
`Display` 只渲染安全结果。

当 URI 诊断属于更大的事件时，使用 `session.uri()`：

```rust
use qubit_redact::Redactor;

let redactor = Redactor::default();
let mut session = redactor.session();
let safe = session.uri().redact_uri_str("https://example.test/path");
assert!(safe.log_safe_text().as_str().contains("example.test"));
```

## 安全边界与验证

- 未知字段默认原样通过，除非配置 `UnknownFieldPolicy::Redact(...)`。
  `RedactionPolicy::strict()` 提供以 `Sensitivity::Secret` 遮盖未知字段的边界预设，默认策略语义不变；
  为所有可控字段名配置规则。本库不是通用秘密探测器。
- 允许规则会有意披露数据且优先级更高；优先使用精确允许规则。
- 不要直接格式化 `RedactedText`；先调用 `escape_for_log()`。
- 领域对象或 Map 视图的 `Debug` 与 `Display` 默认受诊断预算限制；需要不同的显式限制时
  调用 `with_output_limit()`。
- 不要把 `RedactMut` 当作内存擦除机制。
- 只有接受披露风险后，才启用 `TextBodyPolicy::PassThrough`、
  `UnkeyedJsonValuePolicy::PassThrough` 或 `UrlPathPolicy::Preserve`。

| 情况 | 处理方式 |
| --- | --- |
| 可控字段仍然可见 | 添加显式规则；未知字段会原样通过。 |
| 后缀规则披露范围过大 | 优先改用精确规则，或删除后缀 allow 规则。 |
| 策略构建失败 | 检查返回的 `PolicyError`，不要回退到宽松策略。 |
| 全局策略已安装 | 处理 `InstallGlobalPolicyError`；需要隔离时传递显式策略。 |
| 结构化 body 不合法或已截断 | 记录安全结果，并检查 `BodyRedactionStatus::Redacted(reason)`。 |
| 日志行包含控制字符或 Unicode 行序字符 | 通过 `escape_for_log()` 跨过标量日志边界。 |
| 需要内存擦除 | 不要依赖 `RedactMut`；使用专门的 zeroization 设计。 |

发布影响行为或示例的变更前，运行完整 feature 集：

```bash
cargo test --all-features
./ci-check.sh
```

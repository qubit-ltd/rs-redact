# qubit-redact 用户手册

[README](../README.zh_CN.md) · [英文用户手册](user_guide.md) · [derive 说明](../derive/README.zh_CN.md)

## 手册目标与读者

适用于 qubit-redact 0.7 的应用和库作者：先跑通日志和业务序列化共存，再配置领域类型、输入格式和预算。

## 安装与实战：登录诊断

下面的依赖配置支持本节所有示例。

```toml
[dependencies]
qubit-redact = { version = "0.7", features = ["derive", "serde", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact)]
#[redact(crate = qubit_redact)]
#[redact(serde, debug)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

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

```rust
use qubit_redact::{Redact, Redactor};

#[derive(Redact, serde::Serialize)]
#[redact(crate = qubit_redact)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

let login = Login { user: "ada".into(), password: "raw-secret".into() };
assert!(serde_json::to_string(&login).expect("business JSON").contains("raw-secret"));
assert!(!Redactor::standard().to_json(&login).expect("redacted JSON").contains("raw-secret"));
```

只有需要让源对象被直接序列化时也输出脱敏内容，才添加 `#[redact(serde)]`。类型既没有普通
`Serialize`，也没有 `#[redact(serde)]` 时，不能直接序列化源对象；只要生成的投影能够序列化
字段，view 和 `to_json()` 仍可用。若字段缺少所需能力，view 的文本格式化仍可用；但结构化
序列化该 view 或调用 `to_json()` 会产生编译期 trait-bound 错误。

内置等级叶子包括字符串、字符、布尔、整数、浮点数，以及 `serde` 下的 BigDecimal。
等级容器包括引用、Option、Vec、切片、数组、Box/Rc/Arc、VecDeque、LinkedList、集合、堆、
标准 Map 和最长 12 项 tuple。Map 的普通 level 处理 value，保留 key；要隐藏 key 使用对应属性。
文本 Map 放行路径和 keyed_by 需要 Debug；仅使用 level 的 RedactScalar 不要求 Debug。

### 手写业务键包装的嵌套值

手写 `Redact` 实现时，如果一个 `Redact + Debug` 子值由业务键决定策略，可调用
`fields.keyed_nested(display_name, business_key, value)`。业务键公开时，该方法会递归调用子值，
因此子字段规则、JSON 遍历和 inspection 仍然生效；业务键敏感时，整个载荷作为一个值掩码；
disabled 策略则输出原值。这避免了公开包装通过 `Debug` 回退泄露内部 secret。

```rust
use qubit_redact::{Redact, RedactionWriter, Sensitivity};

struct NamedPayload { name: String, payload: Payload }
#[derive(Debug)]
struct Payload { password: String }

impl Redact for Payload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.sensitive(Sensitivity::Secret, "password", || &self.password);
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
```

Serde 支持 rename/rename_all、枚举 tag/content/untagged、transparent、skip、skip_serializing、
skip_serializing_if。支持普通或 skip 字段上的 with/serialize_with；不能与观察原值的敏感模式组合。
flatten 不受支持。JSON 文本字段序列化后仍是字符串，已解析 Value 字段保留 JSON 结构。

### 标量 newtype

```rust
use qubit_redact::{Redact, RedactScalar, Redactor};

#[derive(RedactScalar)]
#[redact(crate = qubit_redact)]
struct Id(u64);

#[derive(RedactScalar)]
#[redact(crate = qubit_redact)]
struct UserId { value: String }

#[derive(Redact)]
#[redact(crate = qubit_redact)]
#[redact(serde)]
struct Account {
    #[redact(level = "secret")]
    id: Id,
    #[redact(level = "secret")]
    user_id: UserId,
}

let account = Account { id: Id(42), user_id: UserId { value: "raw-id".into() } };
assert_eq!(Redactor::standard().to_json(&account).expect("account JSON"),
    r#"{"id":"<redacted>","user_id":"<redacted>"}"#);
```

### 第三方 Display 类型

显式选择文本表示。High/Secret 不触发 Display，Low/Medium 和 disabled 按需格式化，
资源预算仍生效；disabled 下也保持这里明确选择的字符串表示。

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
#[redact(crate = qubit_redact)]
#[redact(serde)]
struct Event {
    #[redact(level = "secret", display)]
    id: ExternalId,
}
let event = Event { id: ExternalId(42) };
assert_eq!(Redactor::standard().to_json(&event).expect("event JSON"),
    r#"{"id":"<redacted>"}"#);
```

### 等级与策略优先级

| 决策来源 | 运行时策略能否提高等级 |
| --- | --- |
| derive 的 level、Display level、map key/value level | 不能：显式等级为最终等级 |
| 手写 fields.sensitive(level, ...) | 可以：参数是最低等级 |
| map、keyed_by、redact_field | 按运行时分类规则决定 |
| 未标注字段、unmarked | 不分类，保持普通输出 |

默认掩码：Low 保留首尾各两个字符，短串全部隐藏；Medium 保留末尾一个字符；
High 输出 `****`；Secret 输出 `<redacted>`。例如 `abcdef` 的 Low 为 `ab****ef`，
Medium 为 `*******f`。业务类型负责选择正确等级，strict 不覆盖显式声明。

### 多个值共享预算

HTTP 的 URL、headers、body 或进程的 argv、env 往往属于同一条诊断事件。使用 batch，
这些值共用一次资源预算；分别调用单值方法或多次使用视图则各用一份预算。
批次按加入顺序消耗额度，后面的项可能因前面的项耗尽预算而降级。
`finish_for_diagnostics(marker)` 给不完整项及无效/跨批次句柄统一返回已转义 marker。
`summary()` 是整批摘要，不是逐项审计接口。

```rust
use qubit_redact::Redactor;
let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-secret");
let output = batch.finish_for_diagnostics("<incomplete>");
assert_eq!(output.text(user).as_str(), "ada");
assert_eq!(output.text(password).as_str(), "<redacted>");
```

## 输入格式与集成

### 渲染其他格式

运行时为 JSON 文本和值、URI、HTTP header/query、环境变量、argv 和进程描述提供有界脱敏。
每种格式保留自身解析和转义规则，同时共享策略决策和事务预算。

解析 JSON 时输入只被借用且保持不变：

```rust
use qubit_redact::Redactor;

let value = serde_json::json!({"password": "raw", "visible": "shown"});
let output = Redactor::standard().redact_json_value(&value);
let inspection = Redactor::standard().inspect_json_value(&value);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(value["password"], "raw");
let _ = inspection;
```

`RedactionBatch::redact_json_value` 以及其他批处理方法共享预算。调用
`finish_for_diagnostics` 后，句柄选择完整项的文本或已转义的降级标记；
`summary()` 描述整个批次。

JSON 文本只解析一次，解析过程同时完成结构准入并构造 admitted tree。非法 JSON 或遍历
超限时会整体安全降级。借用 `Value` 的路径不会复制、转成字符串或修改调用方对象；
领域实现可用 `fields.json_value("payload", &value)` 写入不带额外字符串引号的 JSON 值。
序列实现则应逐项调用 `items.json_value_item(&value)`，它会执行同样的递归 JSON 策略。对于
声明数据类型为 JSON 的下游集合，这一点尤其重要：每一项都必须按 JSON 结构遍历，不能作为
不透明标量格式化。

```rust
use qubit_redact::Redact;
use qubit_redact::RedactionWriter;

struct Documents(Vec<serde_json::Value>);

impl Redact for Documents {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.sequence(|items| {
            items.for_each(&self.0, |items, value| {
                items.json_value_item(value);
            });
        });
    }
}
```

JSON 文本采用 `qubit-json` 的明确数字契约：负整数必须装入 `i64`，非负整数必须装入 `u64`，
小数/指数必须得到有限 `f64`。越界文本沿用安全降级的无效 JSON 路径；serde_json 旧私有
Number 标记键是普通对象键。

### 在同一个批处理中处理完整 HTTP 交换

本示例需要启用 runtime 的 `http` feature，并在依赖中添加 `http = "1"`。

同一条诊断事件的 URL、header 和捕获 body 应进入同一个事务：

```rust
use http::{HeaderMap, HeaderValue};
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

let mut headers = HeaderMap::new();
headers.insert("authorization", HeaderValue::from_static("Bearer raw-token"));
let content_type = HeaderValue::from_static("application/json");
let body = br#"{"user":"ada","password":"raw-password"}"#;

let mut batch = Redactor::standard().batch();
let url = batch.redact_http_url("https://example.test/login?token=raw-token");
let headers_handle = batch.redact_http_headers(&headers);
let body_handle = batch.redact_http_body(BodyCapture::complete(body), Some(&content_type));
let output = batch.finish_for_diagnostics("<redaction incomplete>");

for handle in [url, headers_handle, body_handle] {
    assert!(!output.text(handle).as_str().contains("raw-"));
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

```rust
use qubit_redact::Redactor;

let candidate = "https://example.test/?token=raw-token";
let acceptable = Redactor::strict()
    .inspect_uri(candidate)
    .is_ok_and(|inspection| !inspection.contains_sensitive());
assert!(!acceptable);
```

### 处理 argv、环境变量和进程诊断

调用方知道参数契约时，应优先显式标记 argv。启发式 argv 能识别受支持的 option 形式，但不是
shell parser：

```rust
use std::ffi::OsStr;

use qubit_redact::{Redactor, Sensitivity};
use qubit_redact::formats::argv::ArgvItem;

let arguments = [
    ArgvItem::plain(OsStr::new("--server=example.test")),
    ArgvItem::sensitive(OsStr::new("raw-token"), Sensitivity::Secret),
];
let variables = [(OsStr::new("PASSWORD"), OsStr::new("raw-password"))];
let output = Redactor::standard().redact_process(OsStr::new("client"), arguments, variables);
assert!(!output.text().as_str().contains("raw-"));
```

### Feature 选择

| Feature | 提供的能力 |
| --- | --- |
| `derive` | `#[derive(Redact)]`, `#[derive(RedactScalar)]` |
| `serde` | derive/domain 的结构化 Serde 适配器与 BigDecimal 支持 |
| `json` | JSON 文本及借用的 `serde_json::Value` |
| `http` | JSON、URL、header、form、multipart 和 body capture |
| `uri` | 通用 URI 解析与脱敏 |

只使用标量和手写领域实现时可保持默认空 feature 集。在 0.7 版本系列中，`serde` 继续包含
BigDecimal 支持；若要拆分这项依赖，应在后续破坏性版本中提供明确的 feature 迁移说明。

## 进阶用法

### 检查决策与控制策略

检查 API 会报告规则匹配、敏感度和完成状态，但不会发布原始值。它适合在确定日志或序列化
边界前解释某字段为何会被掩码。

建议构造一份不可变策略，再共享生成的 `Redactor`。builder closure 具有事务语义：字段规则
无效时，原 builder 不会受到部分修改。

```rust
use qubit_redact::{RedactionPolicy, Redactor, Sensitivity};

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
```

`RedactionPolicy::disabled()` 是显式关闭保密脱敏的选项，也是框架有意保留的进程级调试
逃生口。字段、JSON、URI、HTTP、环境变量、argv、进程、derive 字段模式和生成的 Serde
输出都会恢复原值，但仍受运行时资源上限约束。控制字符转义也仍然生效，但这两项机制都不
表示结果已经脱敏。框架只负责执行所选策略；是否有权禁用、在哪个环境和时机禁用，以及误用
后果都由下游负责。让不可信请求控制该开关通常是不安全的，但阻止下游故意或错误调用 API
不属于框架保证。

```rust
use qubit_redact::{RedactionPolicy, Redactor};

let mut policy = RedactionPolicy::disabled();
assert!(policy.is_disabled());
policy.set_disabled(false);
let output = Redactor::new(policy).redact_field("password", "raw-secret");
assert!(!output.summary().is_redaction_disabled());
assert!(!output.text().as_str().contains("raw-secret"));
```

策略启用时，`Complete`、`Truncated` 和 `Exhausted` 文本都应保持保密安全。只有调用方
关心完整性、审计原因或重试决策时才检查 `summary().completion()` 与
`summary().reasons()`，不要解析 `<truncated>` 等文本标记推断状态。若 inspection 用于
安全决策，任何检查错误都表示分类不完整，应按敏感处理。

`Redactor::replace_application_default()` 影响之后调用 `application_default()` 取得的对象，
以及每次重新获取快照的生成格式化代码。已经创建的 `Redactor`、文本组合器和批处理对象继续
持有原有不可变快照；替换不会追溯切换正在进行的工作。

## 预算计量与 0.7 迁移

| 入口 | 结构与输入限制 | Serde 逻辑载荷 | 最终编码字节 |
| --- | --- | --- | --- |
| 字段、领域文本、composer、batch | 各入口共享事务准入 | 不适用 | `max_output_bytes` |
| view 或派生源对象的 `Serialize` | 共享 Serde scope | `max_serde_payload_bytes` | 调用方 writer 控制 |
| `to_json` | 共享 Serde scope | `max_serde_payload_bytes` | `max_output_bytes` |
| `redact_json` / `redact_json_value` | 文本事务与 JSON 专有限制 | 不适用 | `max_output_bytes` |

`max_input_bytes` 默认 64 KiB；两个输出相关限制各默认 16 KiB。它们均允许 0。
Serde 载荷与最终输出限制超过 `isize::MAX` 时策略构造报错。
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
`finish_for_diagnostics(marker)`、`text_or_marker` 等发布后的展示替代会转义 marker，
但 marker 及调用方日志前后缀不计入原事务 `output_bytes` 或 `max_output_bytes`。
预算约束库可控制的准入和写入，不抢占 Display/Serialize 内部的任意计算或调用前的分配。

## 错误与诊断

当调用方需要区分完整结果与预算或解析降级时，检查 `summary().completion()`、
`summary().reasons()` 和 `summary().usage()`；不要解析展示文本来推断状态。严格的展示路径可用
`complete_text()` 和 `into_complete_text()` 拒绝不完整结果；诊断展示可用 `text_or_marker()` 和
`into_text_or_marker()` 选择明确的降级标记。若检查结果用于安全判断，任何检查错误都意味着
分类不完整，应按敏感结果处理。

## 排障

- 发现原值时，先检查 `output.summary().is_redaction_disabled()` 以及创建文本组合器或
  批处理对象时采用的策略快照。
- 出现非预期截断时，检查 `completion()`、`reasons()` 和 `usage()`；同一事务内的操作
  会有意共享资源上限。
- 字段未命中时，核对字段名并复查所有未标注字段；运行时不会推断业务敏感度。

## 限制与最佳实践

- 应依据业务领域知识标记敏感字段；`unmarked` 和未标注的 derive 字段会有意保持可见。
- 不要将 `RedactionPolicy::disabled()` 暴露给请求控制的输入；它会恢复原值，只适合作为进程级
  调试逃生口。
- 本 crate 只保护经过其运行时的调用，不擦除源对象内存，也不保护无关日志或序列化路径。

## 延伸阅读

参见 [README](../README.zh_CN.md)、[英文用户手册](user_guide.md)、
[API 文档](https://docs.rs/qubit-redact)和
[derive 说明](../derive/README.zh_CN.md)。

验证本地检出内容可运行：

```bash
cargo test --all-features
./align-ci.sh
./ci-check.sh
```


## 许可证

Apache-2.0，详见 [LICENSE](../LICENSE)。

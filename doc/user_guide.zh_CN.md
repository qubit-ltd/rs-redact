# qubit-redact 用户手册

[README](../README.zh_CN.md) · [英文用户手册](user_guide.md) · [设计文档](design.zh_CN.md) · [derive 说明](../derive/README.zh_CN.md)

## 手册目标与读者

本手册面向使用 `qubit-redact` 0.6 构建日志与诊断边界的应用和库作者。适用于值可能进入
日志、错误信息或技术支持工具，且应用必须自行判断字段敏感性的场景。它不保护绕过运行时的输出，
也不会擦除源对象内存。

## 概念模型

`Redactor` 持有不可变策略快照。文本组合器（composer）或批处理（batch）会开启一次有界
渲染事务，发布拥有独立内容的文本和摘要：

```text
借用的值 -> 策略判定 + 事务预算
            -> 文本组合器：RedactionTextOutput
            -> 批处理：句柄 + 安全降级的诊断视图
            -> 检查：Result<RedactionInspection, Error>
```

单值便利方法和文本组合器返回 `RedactionTextOutput`；批处理通过不透明句柄（handle）发布可独立
寻址的诊断文本，检查（inspection）返回不渲染文本的 `Result`。每个已渲染操作
都携带安全文本和 `RedactionSummary`。启用脱敏时，
`Complete`、`Truncated`、`Exhausted` 三种状态下发布的文本都满足保密安全要求。后两种
状态表示诊断信息不完整，不表示源数据已经泄露。因此 `Debug`、`Display` 和普通诊断日志
可以直接使用 `output.text()`；强制这些调用方逐一分析原因，也不会产生可执行的恢复动作。

只有审计、重试、业务判断或结构化输出契约依赖完整性时，才检查 `completion()` 和
`reasons()`。这类调用方可以用 `complete_text()` / `into_complete_text()` 拒绝不完整结果，
或用 `text_or_marker()` / `into_text_or_marker()` 选择展示降级标记。`Truncated` 保留安全的
已接纳表示，`Exhausted` 表示共享预算无法容纳完整替代；原因集合可说明 JSON、form、
multipart 等解析降级和预算限制。

## 实战场景：发布不含密码的登录诊断信息

认证服务需要在一条诊断事件中记录用户名和含密码的请求字段：用户名应保留，密码不能出现在输出中，
预算不足时还要使用统一的降级标记。批处理会让这组值共享同一份策略和预算：

```rust
use qubit_redact::Redactor;

let mut batch = Redactor::standard().batch();
let user = batch.redact_field("user", "ada");
let password = batch.redact_field("password", "raw-password");
let output = batch.finish_for_diagnostics("<redaction incomplete>");

assert_eq!(output.text(user).as_str(), "ada");
assert!(!output.text(password).as_str().contains("raw-password"));
```

`finish_for_diagnostics()` 会把不完整项目、无效项目和其他批处理创建的句柄都映射成同一个
已转义标记，不返回 `Result`。这有意让诊断展示在无法解析时安全降级，而不再暴露一套并行的
可失败发布模型。

## 安装与最小配置

加入依赖后，只启用应用实际使用的集成能力：

```toml
[dependencies]
qubit-redact = { version = "0.6" }
```

默认 feature 集为空。使用 `#[derive(Redact)]` 时启用 `derive`；派生字段使用生成的序列化
适配器时还要启用 `serde`。直接使用脱敏序列化也需要 `serde`；只有处理相应输入格式时才启用
`json`、`http` 或 `uri`。

## 核心工作流

### 渲染领域值

实现小型运行时 trait，或在下游 crate 中使用 derive：

```rust
use qubit_redact::{Redact, RedactionWriter, Redactor, Sensitivity};

struct Login { user: String, password: String }

impl Redact for Login {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Login", |fields| {
            fields.unmarked("user", || self.user.as_str());
            fields.sensitive(Sensitivity::Secret, "password", || self.password.as_str());
        });
    }
}

let login = Login { user: "ada".into(), password: "raw".into() };
let output = Redactor::standard().redact(&login);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(login.password, "raw");
```

子系统需要显式策略时使用 `Redactor::new(policy)`。运行时没有可变脱敏 API，也不提供内存擦除。

### 选择字段写入方式

`RedactionWriter` 提供显式字段决策：

- `unmarked(name, access)` 输出经过审查的普通值；
- `sensitive(level, name, access)` 应用敏感等级掩码；
- `nested(name, value)` 委托给另一个 `Redact` 实现；
- `map(name, value)` 对支持的 Map 按 key 处理；
- `keyed_value(name, key, value)` 使用兄弟运行时 key 对单个字段值分类，
  语义与一条 Map entry 相同；
- `json(name, value)` 递归处理 JSON；
- `skipped(name, access)` 省略字段且不渲染其值。

每个操作都参与同一个输出预算和摘要。未标注字段会有意保持原样，因为敏感性属于下游业务
领域知识，通用框架无法从 Rust 类型、字段名或当前内容中可靠推断。现实中普通字段占绝大
多数，要求它们逐一声明“不敏感”只会增加噪声，并不会增加有效知识。下游必须显式标记可能
包含敏感数据的字段，并在领域模型变化时重新审查；严格策略（strict policy）和检查 API 都不会
覆盖这个领域决策。

显式 `#[redact(level = "...")]` 是字段的最终敏感等级，文本、检查结果和 Serde
均以它为准。运行时名称规则、敏感等级下限和 strict 模式都不会覆盖它。`sensitive_value`
遵循同一规则；手写 `sensitive` API 声明的则是最低敏感等级。disabled 跳过脱敏，仍保留
资源限制。

按运行时业务名称分类时，使用 `keyed_value` 或惰性 Debug 访问器
`keyed(name, key, access)`。`NamedValue` 和 `NamedMultiValues` 按实际 `name`
分类，与展示字段名无关。

遍历序列或 Map 时使用构建器的 `for_each(values, callback)`，在取出或格式化被拒绝的
元素前停止。构建器无法中断调用方的手写循环。迭代器上界未知时，元素预算耗尽会保守地
报告截断，不再取出额外元素探测是否结束。

Serde 在嵌套值之间共享深度、节点、集合元素、输入字节及标量输出字节预算，覆盖普通
字段、Map key、disabled 输出和自定义 serializer。无法准入的普通值返回序列化错误；
标记过的值在预算足够时可以输出不透明替代值。自定义 serializer 只执行一次，且必须
传播 serializer 错误。输出预算计算标量内容字节，不包含格式标点、字段标签及转义开销。
若需限制最终编码字节数，还应单独限制目标 writer。普通 serializer 重入另一个脱敏
serializer 时仍共享调用方预算，中间值可能被保守地重复计费。自定义 formatter/serializer
仍是受信任代码，预算不能抢占其执行。

标量字段 API 接受惰性的 `Display` 值。运行时先判定敏感等级，再决定是否格式化；因此
`High` 和 `Secret` 字段不会触发格式化。只有 `Debug` 的值可以借助 `format_args!`：

```rust
use std::fmt;

use qubit_redact::Redactor;

struct Request;

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("reviewed-debug-view")
    }
}

let request = Request;
let output = Redactor::strict().redact_field(
    "request",
    &format_args!("{request:?}"),
);
assert!(!output.text().as_str().is_empty());
```

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

`RedactionBatch::redact_json_value` 以及其他批处理方法会共享预算，并发布可解析为最终文本
和摘要的句柄。

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
            for value in &self.0 {
                items.json_value_item(value);
            }
        });
    }
}
```

JSON 文本采用 `qubit-json` 的明确数字契约：负整数必须装入 `i64`，非负整数必须装入 `u64`，
小数/指数必须得到有限 `f64`。越界文本沿用安全降级的无效 JSON 路径；serde_json 旧私有
Number 标记键是普通对象键。

### 在同一个批处理中处理完整 HTTP 交换

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
| `derive` | `#[derive(Redact)]` |
| `serde` | derive/domain 的结构化 Serde 适配器与 BigDecimal 支持 |
| `json` | JSON 文本及借用的 `serde_json::Value` |
| `http` | JSON、URL、header、form、multipart 和 body capture |
| `uri` | 通用 URI 解析与脱敏 |

只使用标量和手写领域实现时可保持默认空 feature 集。在 0.6 版本系列中，`serde` 继续包含
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

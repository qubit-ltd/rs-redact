# rs-sanitize 0.3 API 与匹配语义设计

## 目标

将 `qubit-sanitize` 升级为 `0.3.0`，收紧字段名 suffix 匹配语义，补全
`SensitiveFields` 的集合操作，并让无外部依赖的 core 能力始终可用。同时修复
`rs-http` 合并 debug 脱敏策略时可能降低内置敏感级别的问题，增加跨 adapter 的
no-leak 性质测试，并降低公开文档对通用脱敏能力的承诺。

## 范围

本次修改覆盖：

- `rs-sanitize` 的版本、Cargo features、公开 API、匹配算法、测试和文档；
- 直接依赖 `qubit-sanitize` 的 `rs-command` 与 `rs-http` 的依赖声明；
- `rs-http::LogSanitizer::for_debug` 的敏感字段合并语义和回归测试。

本次不修改 CI，不迁移 `rs-llmsdk-core`，不处理 `rs-http` 已存在的
`qubit-datatype` dev-dependency 版本问题。

## 版本与下游依赖

`rs-sanitize/Cargo.toml` 的 crate 版本升级为 `0.3.0`。所有直接下游只声明
`0.3` 版本范围，不出现 patch 版本号；在 `0.3.0` 发布前同时使用相对路径：

```toml
# rs-command
qubit-sanitize = {
    version = "0.3",
    path = "../rs-sanitize",
    default-features = false,
}

# rs-http
qubit-sanitize = {
    version = "0.3",
    path = "../rs-sanitize",
    default-features = false,
    features = ["web", "http"],
}
```

两个下游的 `Cargo.lock` 随依赖来源和版本一起更新。`rs-platform` 和
`rs-llmsdk-core` 没有直接依赖 `qubit-sanitize`，本次不修改。

## Feature 设计

core 类型、`ArgvSanitizer` 和 `EnvSanitizer` 不再由 feature 控制，始终编译。
Cargo features 调整为：

```toml
default = ["web", "http"]
web = ["dep:form_urlencoded", "dep:url"]
http = ["dep:form_urlencoded", "dep:http", "dep:serde_json"]
```

- `--no-default-features` 提供 core、argv 和 env 能力，且不引入可选依赖；
- `web` 提供 URL 和 URL-encoded form adapter；
- `http` 提供 HTTP header/body adapter；
- `web` 与 `http` 继续相互独立，共享的 form helper 在任一 feature 开启时编译；
- 删除 `core` feature，并同步修改 README、Rustdoc 和 feature matrix 说明。

## SensitiveFields 集合 API

保留 `insert(&str, SensitivityLevel)` 的显式覆盖语义，新增：

```rust
pub fn remove(&mut self, field: &str) -> Option<SensitivityLevel>;
pub fn clear(&mut self);
pub fn merge_strongest(&mut self, other: &SensitiveFields);

impl<S> FromIterator<(S, SensitivityLevel)> for SensitiveFields
where
    S: AsRef<str>;
```

- `remove` 使用与插入和查询相同的字段名规范化规则；空规范化结果返回 `None`；
- `clear` 删除全部字段；
- `merge_strongest` 对新字段直接插入，对同一规范化字段保留更高等级；等级顺序为
  `Low < Medium < High < Secret`；
- `FromIterator` 逐项使用现有 `insert` 语义，因此重复字段由迭代顺序中的最后一项
  覆盖；需要强等级合并时必须显式调用 `merge_strongest`。

`rs-http::LogSanitizer::for_debug` 改用 `merge_strongest`。调用方可以提高内置字段
等级，但不能把 `authorization`、`password` 等内置字段降级。

## ExactOrSuffix 匹配

### 当前问题

当前实现先删除分隔符并转小写，再对完整规范化字符串执行 `ends_with`。这会把
没有语义边界的 `notapikey` 误判为带上下文前缀的 `api_key`。

根因是字段名规范化丢失了 suffix 起点处的 token 边界信息，而 suffix 算法仍把
任意字符位置当作合法起点。

### 新算法

匹配顺序保持为：

1. 先执行现有规范化精确匹配；
2. `Exact` 模式在精确匹配失败后返回 `None`；
3. `ExactOrSuffix` 模式把候选字段名拆成语义 token；
4. 只从 token 边界开始组合规范化 suffix，并与已配置规范化字段比较；
5. 多个字段命中时继续选择规范化长度最长者。

token 边界包括：

- `_`、`-`、`.` 和 Unicode whitespace；
- 小写字母或数字到大写字母的 camelCase 边界；
- 连续大写缩写到普通单词的边界，例如 `APIKey` 拆为 `API`、`Key`。

预期行为：

| 候选名 | 配置名 | 结果 |
| --- | --- | --- |
| `OPENAI_API_KEY` | `api_key` | 匹配 |
| `openaiApiKey` | `api_key` | 匹配 |
| `openai-api-key` | `api_key` | 匹配 |
| `apiKey` | `api_key` | 由规范化精确匹配命中 |
| `notapikey` | `api_key` | 不匹配 |
| `monkey` | `key` | 不匹配 |

不为无分隔符、无大小写边界的拼接字符串推测单词边界。字段名通常很短，默认字段
数量有限，因此继续采用线性字段扫描；本次不引入索引或缓存。

## URL path 边界

不增加 URL path token 猜测逻辑。

RFC 3986 只定义 path 和 segment 的通用语法，segment 的业务语义由具体 scheme、
协议或应用定义。OAuth Bearer 标准定义 header、form body 和 query 传输方式，未定义
path token。Slack incoming webhook 等实际服务会把秘密放入厂商特定的 path 结构，
但这些结构之间没有可安全复用的通用规则。

`UrlSanitizer` 因此继续：

- 掩码 userinfo、password 和 fragment；
- 按 query 参数名脱敏 query value；
- 原样保留 path。

增加测试固定该行为，并在 Rustdoc 与 README 中明确：调用方必须针对已知 webhook
或业务路由在协议层处理敏感 path。

## JSON 与不透明内容边界

JSON、NDJSON、form 和 multipart 继续只依据结构化字段名脱敏。不会对任意 value、
不透明文本或非敏感字段执行关键词、正则或熵扫描。

文档明确以下内容不在保证范围内：

- 非敏感 JSON 字段中承载的业务秘密；
- 顶层 JSON scalar 中的秘密；
- URL path 中由特定服务定义的 webhook/token；
- 调用方显式选择 `TextBodyPolicy::PassThrough` 后的不透明文本。

## 公开枚举演进

所有由 crate 公开导出的枚举增加 `#[non_exhaustive]`，包括：

- `SensitivityLevel`；
- `SensitiveFieldPreset`；
- `NameMatchMode`；
- `MaskPolicy`；
- `TextBodyPolicy`。

这是 `0.3` 的有意兼容性调整，使后续增加等级、预设、策略或匹配模式时不必再次
破坏下游 exhaustive match。crate 内部仍可保持穷尽匹配；下游需要 wildcard arm。

## 文档措辞

README 和 Rustdoc 不再笼统声称输出是 `log-safe`，统一表达为“按已配置字段名和已
支持结构进行脱敏的诊断表示”。文档同时说明：

- 默认字段集合是常见字段起点，不是完整秘密词典；
- `ExactOrSuffix` 只识别明确 token 边界；
- adapter 不扫描任意 secret；
- URL path 和业务 payload 需要调用方根据协议处理；
- body 输出用于诊断，不是可回放的原始 HTTP body。

README 中的依赖示例升级到 `0.3`。core-only 示例只使用
`default-features = false`，不再引用已删除的 `core` feature。

## 测试策略

实现严格遵循测试先行：

1. 先补 `notapikey`、`monkey` 等误匹配回归测试，确认当前算法失败；
2. 再补 camelCase、缩写、显式分隔符和最长 suffix 正向测试；
3. 实现 token-aware suffix 算法并运行 core 测试；
4. 先为 `remove`、`clear`、`merge_strongest` 和 `FromIterator` 编写失败测试，再实现；
5. 在 `rs-http` 增加内置等级不可被降级的回归测试，再替换合并逻辑；
6. 为 argv、env、form、URL query、HTTP header 和 HTTP body 增加 no-leak 性质测试。

no-leak 性质测试生成非空、足够长且易于精确查找的随机敏感值，把它放入明确的敏感
字段中，断言完整原值不出现在脱敏输出中。HTTP body 至少覆盖 JSON、NDJSON、form
和 multipart；测试使用真实 adapter，不使用 mock。

feature 验证矩阵至少覆盖：

```text
--no-default-features
--no-default-features --features web
--no-default-features --features http
--all-features
```

最终运行完整测试、Clippy、Rustdoc、格式检查和覆盖率检查。`rs-command` 使用本地
路径依赖运行完整测试。`rs-http` 尝试运行相关测试；若仍被既有
`qubit-datatype ^0.3` 解析问题阻塞，记录真实结果但不在本次扩大范围修复。

## 非目标

- 不引入通用 secret scanner、正则词典、熵检测或回调式内容分析器；
- 不解析或猜测厂商特定 webhook path；
- 不迁移 `rs-llmsdk-core` 或 `rs-platform`；
- 不修改 CI；
- 不修复与本次目标无关的依赖、日志或协议问题；
- 不增加字段匹配缓存或复杂索引。

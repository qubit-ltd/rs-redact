# rs-sanitize 安全加固与 Feature 分层设计

## 目标

修复 `MaskPolicy::PreserveEdges` 的极值溢出和 HTTP Content-Type 优先级问题，
在不拆分 crate 的前提下将公开能力划分为 `core`、`web`、`http` 三组，并合并
URL-encoded form 的重复实现。同时为不透明文本增加默认拒绝的显式策略，补全
Rustdoc、中英文 README、回归测试和性质测试。

## Feature 设计

Cargo feature 定义如下：

```toml
default = ["core", "web", "http"]
core = []
web = ["core", "dep:url", "dep:form_urlencoded"]
http = ["core", "dep:http", "dep:serde_json", "dep:form_urlencoded"]
```

- `core` 导出字段策略、掩码策略、`ArgvSanitizer` 和 `EnvSanitizer`。
- `web` 导出 `UrlSanitizer` 和 `FormUrlEncodedSanitizer`。
- `http` 导出 `HttpHeaderSanitizer` 和 `HttpBodySanitizer`。
- `web` 与 `http` 相互独立，但都依赖 `core`。
- HTTP body 仍支持 URL-encoded form，但不会因此引入完整 `url` crate。
- 默认 feature 保持当前完整公开 API，现有普通依赖无需修改。

新增 Cargo feature matrix，分别验证 `core`、`web`、`http` 和全部 feature 的
check、test、doc；关键组合同时运行 Clippy。

## 掩码溢出修复

`mask_preserving_edges` 对 `prefix_chars + suffix_chars` 使用饱和加法。两者之和
超出 `usize` 范围时按“保留区覆盖整个值”处理，返回完整 replacement，不进入
切片或迭代保留路径。

回归测试使用 `usize::MAX`，要求：

- debug 和 release 均不 panic；
- 输出不包含完整敏感原文；
- 正常前后缀和 Unicode 行为保持不变。

## HTTP Content-Type 优先级修复

只有 Content-Type 缺失时才根据首个非空白字节 sniff JSON。显式 Content-Type
始终优先：

- `application/json` 继续按 JSON 处理；
- `text/plain` 即使以 `{` 或 `[` 开头也按文本策略处理；
- `application/x-www-form-urlencoded` 即使以 `{` 开头也按 form 处理；
- multipart 和 NDJSON 的现有优先级不变。

## 不透明文本策略

新增 HTTP 专属公开枚举 `TextBodyPolicy`：

```rust
pub enum TextBodyPolicy {
    Redact,
    PassThrough,
}
```

`HttpBodySanitizer` 持有该策略，默认值为 `Redact`。提供只读访问器、可变访问器
和链式设置方法，避免把 HTTP 语义放进通用 `FieldSanitizePolicy`。

策略适用于：

- 顶层显式 `text/*` body；
- multipart 中非敏感、非文件且无 Content-Type 的文本 part；
- multipart 中非敏感且声明为 `text/*` 的 part。

`Redact` 返回明确的文本 redaction marker，并保留已有的 preview 截断信息；
`PassThrough` 保持当前原样文本行为。JSON、NDJSON、form、敏感字段、文件、未知
媒体类型和二进制路径不受该策略影响。

该策略不尝试使用正则扫描任意 secret。Rustdoc 和 README 必须明确说明：

- `PassThrough` 是调用方主动接受的诊断风险；
- 不透明文本没有字段结构，无法应用字段名匹配策略；
- 即使结构化内容中，藏在非敏感字段值里的业务秘密也不在通用字段匹配的保证范围内。

## URL-encoded form 复用

抽取私有 helper，输入 `&FieldSanitizer`、form bytes 和 `NameMatchMode`，返回统一
序列化后的 form 字符串。`FormUrlEncodedSanitizer` 与 `HttpBodySanitizer` 都调用
该 helper，继续保持字段顺序、重复 key 和 percent-encoding 行为。

helper 在 `web` 或 `http` 任一 feature 开启时编译，不成为公开 API。

## 测试策略

严格按测试先行执行：

1. 先补掩码极值测试并确认旧实现失败，再修复溢出。
2. 先补显式 text/form Content-Type 测试并确认旧实现失败，再修复 sniffing。
3. 先增加文本策略默认值、显式透传、multipart 行为测试，再实现策略。
4. 以独立 feature 构建失败作为 feature 分层和共享 form helper 的红灯验证。
5. 增加性质测试，覆盖随机掩码参数和任意 HTTP body 字节，验证不 panic；对配置为
   敏感的值验证不会完整出现在输出中。
6. 运行全部回归测试、feature matrix、Clippy、Rustdoc、格式检查和覆盖率检查。

## 文档与兼容性

- 默认 features 保持当前全部 API 可用。
- `TextBodyPolicy::Redact` 改变显式文本 body 的默认渲染行为，这是有意的安全默认
  值调整。
- 所有新增公开枚举、方法、marker 行为和 feature gate 都补全英文 Rustdoc。
- `README.md` 与 `README.zh_CN.md` 同步增加 feature 表、默认文本策略、
  `PassThrough` 风险和迁移示例。
- 本次只修改 `rs-sanitize`；`rs-command` 切换到仅启用 `core` 作为发布后的独立
  下游变更。

## 非目标

- 不引入正则 secret scanner、回调式文本分析器或新的 crate。
- 不解析任意 shell、业务协议或压缩/流式 HTTP body。
- 不在本次跨仓库修改 `rs-command`、`rs-http`、`rs-platform` 或 `rs-llmsdk-core`。

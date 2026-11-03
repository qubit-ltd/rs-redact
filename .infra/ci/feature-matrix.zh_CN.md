# Feature 矩阵设计

Feature 矩阵用于检查会改变编译结果、公开 API 或行为的 Cargo feature 边界。它是经过挑选的组合集合，不是把所有 feature 做笛卡尔积。只有当一个组合覆盖了独立边界或交互路径时，才保留该组合；新增组合时需要说明它覆盖的内容。

## Feature 关系

crate 提供六个可选 feature：`derive`、`serde`、`bigdecimal`、`json`、`http` 和 `uri`。它们的依赖关系如下：

- `bigdecimal` 会启用 `serde`。
- `json` 会启用 `serde`。
- `http` 会启用 `json`，而 `json` 会启用 `serde`。
- `derive` 和 `uri` 独立于上述集成依赖链。

这些 feature 分别代表可独立选择的能力或可选依赖，因此精简 CI 组合不意味着合并或移除公开 feature。

## 保留的组合

| 矩阵项 | Feature 选择 | 命令 | 覆盖理由 |
| --- | --- | --- | --- |
| `derive` | derive crate，启用其全部 feature | check、test、doc、clippy | 完整验证过程宏 crate。 |
| `core` | 运行时 crate，不启用 feature | check、test、doc、clippy | 保护空默认配置，并覆盖仅在集成未启用时编译的代码。 |
| `derive-core` | `derive` | check、test | 覆盖运行时 crate 仅启用 derive 的路径。 |
| `serde` | `serde` | check、test | 验证不启用 JSON 或其他集成时的 Serde 支持。 |
| `derive-serde` | `derive`、`serde` | test | 验证 derive 与 Serde API 的组合及编译约束测试。 |
| `derive-json` | `derive`、`json`（隐式启用 `serde`） | test | 验证 derive 与 JSON API、投影行为的组合。 |
| `bigdecimal` | `bigdecimal`（隐式启用 `serde`） | test | 覆盖 BigDecimal 序列化与脱敏行为。 |
| `http` | `http`（隐式启用 `json`、`serde`） | test | 覆盖所需 JSON 依赖栈下的 HTTP 集成。 |
| `uri` | `uri` | test | 独立覆盖 URI 支持。 |
| `http-uri` | `http`、`uri`（并隐式启用 `json`、`serde`） | test | 覆盖 HTTP/URI 联合格式处理与策略路径。 |
| `json-arbitrary-precision` | `derive`、`http`、`serde_json/arbitrary_precision` | test | 保留针对任意精度 JSON 行为的检查。 |
| `all-root` | workspace 全部 feature | check、test、doc、clippy | 检查所有能力同时启用时的集成问题。 |

## 为什么不穷举所有组合

Feature 是累加的：启用一个 feature 不会关闭其他 feature 的代码。因此矩阵分别保护两个重要边界：无 feature 构建可发现对可选代码的意外依赖，`all-root` 则验证所有集成能够共同启用。其余条目覆盖独立集成和需要特定组合的源码路径，尤其是 `derive + serde`、`derive + json` 及 `http + uri`。

此前的大多数组合没有对应独有的 `cfg` 路径或单独描述的行为，却重复运行昂贵的集成测试和 compile-fail 测试。当前设计仅在两个边界配置上运行完整的静态与文档检查，在具有独立 feature 行为的配置上运行测试。

新增 feature 或矩阵项时，先确认其依赖关系，以及现有组合未覆盖的 `cfg` 分支、API 契约或行为。只为填补明确的覆盖缺口添加组合。如果失败只涉及某类测试，应优先为该测试族增加定向命令，而不是再增加一组完整矩阵。

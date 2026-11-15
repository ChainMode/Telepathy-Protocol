# 第 01 章 引言

## 1.1 文档目的

本规范定义 **Telepathy Protocol（TP）** 的技术契约：消息格式、交互流程、状态机、安全要求与一致性级别。它是蓝图（`docs/{lang}/blueprint/`）所描绘协议愿景的可实施版本——蓝图回答「为什么需要 TP」，本规范回答「如何正确实现 TP」。

## 1.2 适用范围

### 1.2.1 本规范覆盖

- Fay 与 Fay 之间通过 TP 进行通信的全部消息格式
- 共享语境（SharedContext）的生命周期、资源挂载、访问控制与同步
- 目标（Goal）的协商、执行、子目标 DAG 与咨询模式
- 身份辨识（DID）、人类原型授权（FP 引用）与端到端加密
- 协议协商与跨协议传输（A2A / MCP / REST / Prompt）的映射规则
- 错误处理与三级一致性合规要求

### 1.2.2 本规范不覆盖

| 主题 | 在何处定义 |
|------|----------|
| Fay 内部架构、记忆图谱实现 | 实现自由 |
| 自然人到 iFay 的身份绑定 | FP（Faying Protocol） |
| 人 ↔ Fay 的自然语言交互 | ICP（Interactive Conversation Protocol） |
| Fay 对硬件/客户端的接管 | CAP（Control Authority Protocol） |
| 硬件/OS 向 Fay 推送的环境数据 | DTP（Data Tunnel Protocol） |
| Fay 技能发现 | SSP（Skill Sharing Protocol） |

TP 在协议消息中**引用**这些姊妹协议的产物（如 FP 授权引用），但不规定它们的内部细节。

### 1.2.3 TP 1.0 MVP 与研究轨道边界

- **TP 1.0 MVP 规范边界**：基于**显式消息 Schema**（JSON Schema / TypeScript 类型定义）+ **共享本体与协议契约协商**（`ProtocolContract`）+ **强制结构化文本降级兜底**（Structured Text Fallback），保障异构模型与异构 Agent 运行时之间的确定性互操作与人类原型可审计性。
- **研究轨道（Research Track）**：跨模型原生潜向量传输（Latent Vector Transfer）依赖特定基座模型权重空间对齐，不纳入 TP 1.0 一致性合规强制要求，作为实验性扩展独立演进。

## 1.3 读者对象

- **协议实现者**：构建 TP SDK、桥接器、运行时的工程师
- **Fay 开发者**：基于 TP 实现 iFay 或 coFay 业务能力的工程师
- **集成方**：将既有 A2A/MCP Agent 接入 TP 生态的工程师
- **审计与合规人员**：评估 TP 部署是否满足合规级别要求的角色

## 1.4 文档结构

| 章 | 内容 | 必读对象 |
|---|------|---------|
| 01 引言 | 范围、术语、版本约定 | 所有 |
| 02 合规性 | RFC 2119 关键字、三级一致性级别 | 所有 |
| 03 架构概览 | 三层模型与跨切关注点 | 所有 |
| 04 身份辨识层 | DID、FayProfile、人类原型授权 | 实现者、集成方 |
| 05 认知分享层 | SharedContext、资源、ACL、同步 | 实现者 |
| 06 目标协商层 | Goal 状态机、子目标 DAG、咨询 | 实现者、Fay 开发者 |
| 07 隐私与安全 | 加密、选择性披露、凭证、审计 | 实现者、合规 |
| 08 协议协商 | 通信级别、ProtocolContract 协商 | 实现者、集成方 |
| 09 传输绑定 | TP over A2A / MCP / REST / Prompt | 集成方 |
| 10 错误处理 | 错误码体系、可恢复性分类 | 实现者 |
| 11 数据模型 | 链接 schema 三件套 | 实现者 |
| 12 术语表 | 规范化术语定义 | 所有 |

附录：
- 完整的端到端会话示例
- 测试一致性套件指引
- 与 A2A / MCP 的并存策略

## 1.5 文档惯例

### 1.5.1 规范性关键字

本规范使用 **RFC 2119 / RFC 8174** 定义的关键字：**MUST**、**MUST NOT**、**SHOULD**、**SHOULD NOT**、**MAY**。详见 §02.1。

### 1.5.2 代码与示例

- **JSON 示例**：使用 JSON Schema Draft 2020-12 验证；字段命名采用 `snake_case`。
- **TypeScript 类型**：与 `schema/{version}/schema.ts` 中的定义一一对应。
- **Mermaid 时序图**：用于描述消息序列；箭头方向 = 消息发送方向。
- **MUST / SHOULD / MAY** 在示例和图表中出现时为规范性约束，非斜体的同形词为普通叙述。

### 1.5.3 标识符与字段命名

| 类型 | 规范 | 示例 |
|------|------|------|
| Fay ID | 分类前缀 `ifay_`（自然人分身）或 `cofay_`（组织/公共服务分身）+ 小写 RFC 4648 Base32（16–64 位） | `ifay_alice234567abcdef`、`cofay_bobservice234567ab` |
| 消息 ID | UUID v7（时序可排序） | `01902c4f-1a2b-7000-8000-000000000001` |
| 关联 ID | UUID v4 或 v7 | 同上 |
| 时间戳 | ISO 8601，UTC，毫秒精度 | `2026-05-27T08:30:00.000Z` |
| 持续时间 | ISO 8601 duration | `PT15M`（15 分钟） |
| 字段名 | `snake_case`（自然人授权主体统一使用 `human_prime_id` / `prime_authorization` / `prime_delegation`；`宿主` / `Host` 仅指终端硬件设备或客户端软件应用） | `prime_authorization`、`mounted_resources` |

### 1.5.4 版本标注与科学诚实边界

- **线格式协议版本**（`tp_version`）：统一采用两段式 `MAJOR.MINOR`（协议标识 `TP/1.0`，信封字段规范值为 `"1.0"`，解析器兼容归一化 `"TP/1.0"`）。任何三段式 SemVer 字符串（如 `"1.0.0"` 或 `"TP/1.0.0"`）均属非法线格式，接收方 **MUST** 以 `TP-VER003` 拒绝；跨主版本不兼容（`MAJOR != 1`）**MUST** 以 `TP-VER001` 拒绝。注：`CapabilityDescriptor.version` 描述单个能力自身的工程迭代，仍可使用语义化版本字符串。
- **规范文档与 Schema 快照版本**：以发布日期标识（`YYYY-MM-DD`），与 `schema/2025-10-25/` 及权威规范 Schema `schemas/tp-1.0.json` 同步。`docs/zh-CN/` 为唯一权威源语言。
- **TP 1.0 规范核心与长期研究轨道边界**：
  - **TP 1.0 Normative Core（标准互操作必选核心）**：由（1）显式认知帧 Schema（`CognitiveFrame`）、（2）共享本体与码本版本协商（`OntologyDescriptor`）、（3）强制结构化自然语言回退信道（`StructuredTextFallbackFrame`）三层可验证认知交换栈构成；当双方无共同本体或置信度低于阈值时 **MUST** 无缝回退至可人类审计的结构化文本帧。
  - **Experimental Latent Research Track（可选长期研究轨道）**：TP 1.0 **绝不宣称**跨独立训练异构基座模型的无损原生隐向量直传已获解决。`ExperimentalLatentFrame` 仅在双方通过密码学摘要证明完全同构的 `base_model_digest` 与 `adapter_digest`、且同时附带非空人类可审计摘要（`audit_summary`）与结构化回退帧（`fallback_frame`）时方可在实验轨道启用；异构模型隐向量帧 **MUST** 以 `TP-LAT002` 拒绝。

## 1.6 与蓝图的关系

| 蓝图章 | 规范章 | 关系 |
|-------|-------|------|
| 第 1 章 为什么需要 TP | — | 设计动机背景，规范不复述 |
| 第 2 章 TP 的核心定位 | §03 架构概览 | 蓝图给视角，规范给结构 |
| 第 3 章 三大独特能力 | §05、§07、§08 | 蓝图给概念，规范给契约 |
| 第 4 章 应用场景 | 附录 端到端示例 | 蓝图给故事，规范给消息 |
| 第 5 章 生态定位 | §09 传输绑定 | 蓝图给关系，规范给映射 |
| 第 6 章 设计原则 | §02 合规性的根据 | 原则 → 规范化要求 |
| 第 7 章 交付物与路线图 | — | 项目治理，本规范不涵盖 |

## 1.7 与 Schema 的关系

本规范的所有数据结构均在 `schema/{version}/` 中给出三种等价表达：

| 文件 | 用途 |
|------|------|
| `schema.json` | JSON Schema Draft 2020-12，机器可校验 |
| `schema.ts` | TypeScript 类型定义，IDE 友好 |
| `schema.mdx` | 人类可读文档，字段说明 |

三件套**必须保持同步**。任何字段添加、删除、类型变更都必须同时更新三个文件，并在 `schema/CHANGELOG.md` 中记录。

本规范文本（`docs/{lang}/specification/`）与 schema 之间的关系是：
- 规范定义**行为**（流程、状态机、约束、错误恢复）
- Schema 定义**形状**（字段、类型、必填性）
- 当二者出现冲突时，**Schema 是数据契约的事实标准**；规范行文必须修正以与 Schema 对齐。

## 1.8 反馈与贡献

本规范处于 `draft` 状态，社区反馈通过以下渠道收集：

- **GitHub Issues**：协议设计讨论、bug 报告
- **GitHub Discussions**：开放性问题、用例提议
- **RFC 流程**：重大变更（详见 `docs/{lang}/community/rfc-process.md`，待发布）

`draft` 阶段的目标是将规范打磨到 **2025-10-25** 正式版本。届时规范进入冻结状态，后续变更通过新的日期版本目录管理。

# Telepathy Protocol (TP)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0--draft-blue)](#)

**A cognitive-sharing protocol for Fay-to-Fay communication within the iFay ecosystem.**

MCP lets AI use tools. A2A lets Agents pass messages. TP lets Fays achieve *telepathy* — establishing shared cognitive spaces within authorized trust boundaries, enabling high-fidelity intent transfer through session-level sharing of memory, views, rules, and structured reasoning state.

> **认知共享协议** — TP 不是又一个 agent-to-agent 通信协议，而是让 Fay 在人类原型（Human Prime）或组织授权的信任边界内建立共享认知空间的协议。MCP 让 AI 能用工具，A2A 让 Agent 能传话，TP 让 Fay 能共享认知上下文。

## TP 1.0 MVP Scope & Research Track

- **TP 1.0 MVP (Engineering Baseline)**: Explicit JSON/CBOR schema negotiation, shared ontology/concept-anchor alignment, capability/privacy boundary verification (`PrimeAuthorization` + Faying mandate binding), and **mandatory structured-text fallback** so heterogeneous base models interoperate deterministically with zero silent semantic loss.
- **Latent Vector Track (Research Track)**: Cross-model raw hidden-state / KV-cache / latent-space alignment across heterogeneous model families remains an experimental Research Track and is never required for TP 1.0 conformance.

## Three Unique Capabilities

| Capability | Description |
|---|---|
| **Transport Agnosticism** | TP messages can travel over A2A, MCP, DTP, API, or Prompt — TP governs cognitive semantics and authorization, not transport |
| **Protocol & Ontology Negotiation** | Explicit schema and ontology bridging with mandatory structured-text fallback when Fays run on different base models |
| **Authorized Shared Context** | Session-scoped sharing of memory fragments, view states, and rules strictly bounded by Human Prime (`human_prime_id`) or organizational mandates |

## Quick Start

1. **Explore the Blueprint** — understand why TP exists and how it differs from MCP/A2A:
   - [中文蓝图 (Canonical)](./docs/zh-CN/blueprint/)
   - [English Blueprint](./docs/en/blueprint/)

2. **Review the Schema** — inspect the protocol's data structures:
   - [Draft Schema (JSON)](./schema/draft/schema.json)
   - [Draft Schema (TypeScript)](./schema/draft/schema.ts)
   - [Draft Schema (Documentation)](./schema/draft/schema.mdx)

3. **Read the Draft Specification**:
   - [中文协议规范草案](./docs/zh-CN/specification/draft/)

## Repository Structure

```
├── docs/                 # Multi-language documentation (9 languages; zh-CN canonical)
│   └── {lang}/
│       ├── blueprint/    # Project vision and ecosystem positioning
│       └── specification/# Formal protocol specification (draft / versioned)
└── schema/               # Versioned schema definitions
    └── draft/            # Draft JSON Schema, TypeScript types, and documentation
```

## iFay Ecosystem

TP is one of six sibling protocols in the iFay ecosystem:

| Protocol | Full Name | Role |
|---|---|---|
| **FP** | Faying Protocol | Human Prime ↔ iFay accountability & mandate binding |
| **CAP** | Control Authority Protocol | Hardware terminal & client software takeover governance |
| **DTP** | Data Tunnel Protocol | Negotiated encrypted data channel & DAG provenance |
| **ICP** | Interactive Conversation Protocol | Context-annotated `.ctx` interaction & reaction consent |
| **SSP** | Skill Sharing Protocol | Feed-based skill discovery & invocation |
| **TP** | Telepathy Protocol | Authorized Fay-to-Fay cognitive context sharing |

## License

This project is licensed under the [MIT License](./LICENSE).

# Telepathy Protocol (TP)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Docs License: CC BY 4.0](https://img.shields.io/badge/Docs-CC%20BY%204.0-lightgrey.svg)](./LICENSE-DOCS)
[![Wire Version](https://img.shields.io/badge/wire-TP%2F1.0-blue)](./schemas/tp-1.0.json)
[![SDK](https://img.shields.io/badge/%40ifay%2Ftp--sdk-1.0.0-success)](./package.json)

**A verifiable cognitive-sharing protocol for Fay-to-Fay (`Fay = iFay + coFay`) collaboration within the iFay ecosystem.**

MCP lets AI use tools. A2A lets Agents pass task messages. **Telepathy Protocol (`TP/1.0`)** lets Fays establish authorized, session-scoped shared cognitive spaces within explicit Human Prime (`人类原型`) or organizational mandate boundaries.

> **心灵感应协议（TP/1.0）** — 让分身（`Fay = iFay + coFay`）在人类原型（`Human Prime`）或组织赋灵委托（Faying Mandate）授权边界内建立可审计的认知共享空间（`SharedContext`）。注：`人类原型` / `Human Prime` 专指被映射与服务的自然人；`宿主` / `Host` 仅指终端硬件设备或客户端软件应用。生态内 `公誉链`（`GMChain`）上的 `美誉值`（`MeriToken`）为严格非货币化的社会贡献声誉度量。

---

## Scientific Honesty: TP 1.0 Normative Core vs. Experimental Latent Research Track

TP 1.0 draws a strict, machine-enforced boundary between reproducible engineering interoperability and open deep-learning research:

1. **TP 1.0 Normative Core (Mandatory for Conformance)**:
   - **Layer 1 — Explicit Cognitive Frame Schema (`CognitiveFrame`)**: Structured intent summaries, calibrated confidence (`0..1`), explicit assumptions, constraints, typed entities, and `SharedContext` references.
   - **Layer 2 — Shared Ontology & Codebook Negotiation (`OntologyDescriptor`)**: Handshake negotiation of `ontology_id`, `version`, `codebook_digest`, and quantization tolerance inside `ProtocolContract` (`tier_1_native_tp`).
   - **Layer 3 — Mandatory Structured Natural-Language Fallback (`StructuredTextFallbackFrame`)**: Whenever peers do not share a compatible ontology or frame confidence drops below threshold, communication **MUST** seamlessly downgrade to `tier_3_structured_text_fallback`, guaranteeing 100% cross-model interoperability and Human Prime auditability (`tier_2_ai_generated` is disabled by default as experimental).
2. **Experimental Latent Research Track (Optional, Non-Normative)**:
   - TP 1.0 **never** claims lossless raw hidden-state or latent-vector transfer across independently trained heterogeneous base models.
   - `ExperimentalLatentFrame` (`experimental: true`) is rejected with `TP-LAT002` unless both Fays cryptographically prove identical `base_model_digest`, `adapter_digest`, and vector `dimension` (`ModelHomogeneityAttestation`), **and** attach a non-empty human-auditable `audit_summary` plus a valid `fallback_frame` (`TP-LAT003` if omitted).

---

## Key Wire Guarantees in `TP/1.0`

- **Two-Segment Wire Version (`TP/1.0`)**: Envelopes carry `tp_version: "1.0"` (or qualified `"TP/1.0"`). Three-segment SemVer strings (e.g. `"1.0.0"`) are rejected with `TP-VER003`; major version mismatches return `TP-VER001`.
- **RFC 8785 JCS + `Ed25519` Envelopes**: Deterministic JSON Canonicalization Scheme signatures with `Ed25519` mandatory-to-implement and `ML-DSA-65` reserved as the post-quantum agility slot.
- **5-State `SharedContext` & Deterministic LWW Convergence**: Lifecycle states (`initializing`, `active`, `syncing`, `suspended`, `terminated`) with `collaborative_space` conflict resolution ordered deterministically by monotonic `(sync_version, updated_at, actor_fay_id)`.
- **64 KiB Inline Ceiling & SSRF-Guarded References**: Inline `CognitiveResource` payloads > 64 KiB fail with `TP-RES003`; external `reference` URIs require `https://` and block loopback, RFC 1918 private, link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT, IPv6 ULA, and `file://` targets (`TP-RES002`).
- **In-Band Credential Revocation & Zero-Payload-Leak Audit**: `CallbackCredential` enforces expiry (`TP-C001`), mandatory in-band `credential_revoke` + optional HTTPS `revocation_endpoint` (`TP-C002`), and scope checks (`TP-C003`). Local `SHA-256` hash-chained `AuditRecord` logs store digests only (zero raw payload or token leakage) under Human Prime local retention sovereignty.

---

## `@ifay/tp-sdk` Reference SDK & Verification

`@ifay/tp-sdk` is a zero-runtime-dependency Node.js (`>=20`) ESM reference implementation built solely on `node:crypto`.

```bash
# Run the full unit, property-convergence, bridge, and conformance vector suite
npm test

# Syntax check all ESM modules
npm run lint
```

### SDK Modules

| Module | Subpath Export | Responsibility |
|---|---|---|
| [`src/envelope.mjs`](./src/envelope.mjs) | `@ifay/tp-sdk/envelope` | Two-segment `TP/1.0` validator, `FayID`/`FayIdentity` checks, RFC 8785 JCS canonicalizer, `Ed25519` signer/verifier (`ML-DSA-65` slot) |
| [`src/session.mjs`](./src/session.mjs) | `@ifay/tp-sdk/session` | 5-step `SessionStateMachine`, `ProtocolContract` ontology/fallback negotiator, 3-layer cognitive frame & homogeneous latent gate |
| [`src/shared-context.mjs`](./src/shared-context.mjs) | `@ifay/tp-sdk/shared-context` | 5-state `SharedContextManager`, deterministic LWW merge, 64KB + SSRF `CognitiveResource` guard, `X25519` + `AES-256-GCM` `SelectiveDisclosure`, `CallbackCredentialRegistry`, zero-leak `AuditChain` |
| [`src/goals.mjs`](./src/goals.mjs) | `@ifay/tp-sdk/goals` | Acyclic sub-goal DAG validator (`TP-GOAL002`), bilateral `GoalStateMachine` (`<= 10` rounds), `ConsultationManager` (`<= 5` hops) |
| [`src/bridges.mjs`](./src/bridges.mjs) | `@ifay/tp-sdk/bridges` | Sibling bridges (`FP` mandate check, `CAP` Host-device handoff, `DTP` tunnel stream binding, `SSP` skill schema match, `ICP` `.ctx` & encryption guard) + external `A2A` TaskCard / `MCP` Resource translators with explicit `LossMetadata` |

---

## Repository Layout

```text
├── docs/                              # Multi-language documentation (zh-CN canonical)
│   └── zh-CN/
│       ├── blueprint/                 # Vision and ecosystem positioning
│       └── specification/draft/       # Chinese normative specification chapters (01..12)
├── schemas/
│   └── tp-1.0.json                    # Canonical frozen TP/1.0 JSON Schema (Draft 2020-12)
├── schema/
│   ├── 2025-10-25/                    # Frozen 2025-10-25 snapshot (schema.json, schema.ts, schema.mdx)
│   ├── draft/                         # Synchronized active mirror
│   └── CHANGELOG.md                   # Schema version changelog
├── vectors/
│   └── tp-1.0-conformance.json        # 21 positive & negative conformance vectors
├── src/                               # Zero-dependency @ifay/tp-sdk ESM implementation + index.d.ts
└── tests/                             # Node test suite (envelope, session, shared-context, goals, bridges, vectors)
```

---

## iFay Sibling Protocol Interoperability

| Protocol | Full Name | Interop Boundary with TP/1.0 |
|---|---|---|
| **FP** | Faying Protocol | Verifies `fp_authorization_ref` binding `FayIdentity`, `PrimeAuthorization`, and `PrimeDelegation` to Human Prime mandates |
| **CAP** | Control Authority Protocol | Hands off physical/software Host terminal device execution goals via `cap_handoff_ref` |
| **DTP** | Data Tunnel Protocol | Binds `dtp_tunnel` transport and >64 KiB `DtpTunnelContent` streams (byte compression handled at DTP layer) |
| **SSP** | Skill Sharing Protocol | Network authority for skill discovery; maps SSP Skill Descriptors to `CapabilityDescriptor` with exact JSON Schema matching |
| **ICP** | Interactive Conversation Protocol | Preserves `.ctx` annotations in `icp_annotations` and enforces `EncryptedPayload` on `secret`/`confidential` turns |

## License

**MIT (Reference Implementations, Schemas & Test Vectors) / CC BY 4.0 (Specifications & Blueprints)** — Copyright (c) 2025-2026 ChainMode contributors. See [`LICENSE`](./LICENSE) and [`LICENSE-DOCS`](./LICENSE-DOCS).

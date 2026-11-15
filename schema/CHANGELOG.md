# Schema Changelog

All notable changes to the Telepathy Protocol (TP) schema definitions are documented in this file.

> **Versioning Cross-Reference (Non-Normative)**: Wire protocol messages use two-segment `TP/MAJOR.MINOR` versioning (`tp_version: "1.0"`), whereas schema snapshots in `schema/YYYY-MM-DD/` are anchored by release date. Normative wire compatibility and rejection rules (`TP-VER001`, `TP-VER003`) are governed by [Specification Chapter 1 §1.5.4](../docs/zh-CN/specification/draft/01-introduction.md).

## Format Convention

This changelog follows a format inspired by [Keep a Changelog](https://keepachangelog.com/).

- **Date**: Release or update date in `YYYY-MM-DD` format.
- **Version**: Schema snapshot identifier — either `draft` (active development mirror) or a date-based release tag (`YYYY-MM-DD`).
- **Synchronized Files**: Each `schema/{version}/` directory maintains `schema.json` (JSON Schema Draft 2020-12), `schema.ts` (TypeScript definitions), and `schema.mdx` (human-readable reference), aligned with the canonical normative schema at [`schemas/tp-1.0.json`](../schemas/tp-1.0.json).

---

## [2025-10-25] — TP/1.0 Wire Freeze (Synchronized with `draft` and `schemas/tp-1.0.json`)

Freezes the Telepathy Protocol `TP/1.0` normative wire schema, resolving open engineering and security boundaries across the three-layer architecture.

### Added

- **Normative Wire Primitives**: `ProtocolVersion` (two-segment `1.0` / `TP/1.0`), `FayID` (`ifay_<base32>` / `cofay_<base32>`), `CryptoSuite` (`Ed25519` MTI + `ML-DSA-65` post-quantum agility slot), and `Sha256Digest`.
- **3-Layer Verifiable Cognitive Exchange Stack**:
  - `OntologyDescriptor` — Shared ontology and codebook digest negotiation.
  - `CognitiveFrame` — Explicit structured cognitive frame for shared-ontology sessions.
  - `StructuredTextFallbackFrame` — Mandatory human-auditable structured natural-language fallback frame when ontologies mismatch or confidence drops.
- **Gated Experimental Latent Research Track**: `ModelHomogeneityAttestation` and `ExperimentalLatentFrame` (`experimental: true`), strictly requiring matching `base_model_digest` + `adapter_digest` and an auditable summary (`audit_summary`) plus `fallback_frame`.
- **Proactive Notification, Revocation & Audit Sovereignty**:
  - `ResourceNotification` — Content-free metadata and `SHA-256` digest notification for `resource_notify`.
  - `CredentialRevocation` and `MessageType = "credential_revoke"` — Mandatory in-band revocation returning `TP-C002`.
  - `AuditRecord` — Content-free local `SHA-256` hash-chained audit record under Human Prime retention policy.
- **Sibling & External Interop Metadata**: `DtpTunnelContent` (`dtp_tunnel` transport), `LossMetadata` (`TraceInfo.loss_metadata`), `CapabilityDescriptor.ssp_skill_ref`, `Goal.cap_handoff_ref`, and `MessageEnvelope.icp_annotations`.

### Changed

- **`MessageEnvelope.tp_version`**: Switched from three-segment SemVer to two-segment `TP/1.0` (`"1.0"` or `"TP/1.0"`).
- **`ContextLifecycle` & `SyncState`**: Standardized 5-state lifecycle (`initializing`, `active`, `syncing`, `suspended`, `terminated` + `termination_reason`) and deterministic `last_writer_wins` ordering tuple `(sync_version, updated_at, actor_fay_id)`.
- **`CommunicationTier` & `ProtocolContract`**: Renamed normative tiers to `tier_1_native_tp` and `tier_3_structured_text_fallback` (`tier_2_ai_generated` retained as disabled-by-default experimental enum value); added `crypto_suite`, `shared_ontology`, and `fallback_active`.
- **Human Prime Terminology Alignment**: Enforced `human_prime_id`, `prime_authorization`, `prime_delegation`, and `prime_delegated` across all identity and delegation structures.

### Security

- **`InlineContent` & `ReferenceContent`**: Enforced 64 KiB (`65,536` bytes) maximum inline payload size (`TP-RES003`) and restricted `reference` URIs to `https://` with SSRF blocks against loopback, private, link-local, CGNAT, ULA, and `file://` targets (`TP-RES002`).

# Security Policy — Telepathy Protocol (TP)

## Supported Protocol & Artifact Versions

Security advisories and patches are maintained for the following released Telepathy Protocol baseline and `@ifay/tp-sdk` reference implementation:

| Protocol Version | Normative Artifacts | Security Support |
| --- | --- | --- |
| `1.0` (`TP/1.0`) | `schemas/tp-1.0.json`, `schema/2025-10-25/`, `vectors/tp-1.0-conformance.json`, `src/` (`@ifay/tp-sdk` `1.0.x`) | Supported |
| `< 1.0` (pre-release drafts) | Superseded snapshots | Unsupported |

> **Note on Test Vectors**: Ed25519 and X25519 key material inside `vectors/tp-1.0-conformance.json` and `tests/` consists solely of deterministic public conformance fixtures and MUST NOT be used in production deployments.

## Security Scope

Security disclosures are especially welcomed across the following `TP/1.0` boundaries:

1. **`TP/1.0` Explicit Schema, Ontology & Latent Gate Bounds**: RFC 8785 JCS + `Ed25519` envelope signature bypasses (`src/envelope.mjs`), `OntologyDescriptor` negotiation downgrade/injection flaws, failure to enforce `tier_3_structured_text_fallback` when ontologies diverge, or bypasses of `ModelHomogeneityAttestation`, `audit_summary`, and `fallback_frame` checks on optional `ExperimentalLatentFrame` messages (`TP-LAT002`, `TP-LAT003`).
2. **Mandatory `Human Prime` Authorization & Session Boundaries**: Forgery or bypass of `fp_authorization_ref` binding `Fay` (`iFay` + `coFay`) sessions to **Human Prime** or organizational mandates, unauthorized **Host** terminal device execution handoffs bypassing `cap_handoff_ref`, `SelectiveDisclosure` (`X25519` + `AES-256-GCM`) confidentiality leaks, in-band `CallbackCredential` expiry/revocation/scope bypasses (`TP-C001..TP-C003`), or raw secret leakage into hash-chained `AuditRecord` digests (`src/shared-context.mjs`).
3. **Explicit `semantic_loss` Bridge Disclosure & Resource Guards**: Omission or spoofing of `LossMetadata` / `semantic_loss` disclosures across sibling protocol (`FP`, `CAP`, `DTP`, `SSP`, `ICP`) and external (`A2A`, `MCP`) bridges (`src/bridges.mjs`), failure to enforce `EncryptedPayload` on `secret`/`confidential` ICP turns, Goal DAG cycle/hop limit escapes (`src/goals.mjs`), or bypasses of the 64 KiB inline resource cap and SSRF URI filter (`TP-RES002`, `TP-RES003`).

## Reporting a Vulnerability Privately

**Please do NOT report undisclosed security vulnerabilities via public GitHub Issues, Discussions, or Pull Requests.**

### 1. Primary Channel — GitHub Private Vulnerability Reporting

Submit a confidential report directly via **GitHub Security Advisories**:

- **Report URL**: https://github.com/ChainMode/Telepathy-Protocol/security/advisories/new

### 2. Fallback Channel — Security Email

If GitHub Security Advisories are unavailable to you, send your report via email:

- **Email**: **jah.g@ifay.ai**
- Include `[SECURITY][Telepathy-Protocol]` in the subject line along with affected `@ifay/tp-sdk` module or specification chapter, minimal proof-of-concept envelope/vector, and impact assessment.

## Response & Coordinated Disclosure Timeline

- **Initial Acknowledgment**: Within **72 hours** of receiving the report.
- **Triage & Validation**: Within **7 calendar days** to confirm reproducibility and severity.
- **Coordinated Disclosure Window**: **90 days** from report submission to release patched SDK code, updated conformance vectors, and a coordinated public Security Advisory (crediting the reporter unless anonymity is requested).

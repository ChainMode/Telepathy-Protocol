# Contributing to Telepathy Protocol (TP)

Thank you for your interest in contributing to **Telepathy Protocol (`TP/1.0`)** and `@ifay/tp-sdk`! This guide explains how to set up the repository, run verification suites, maintain schema and vector stability, sign off commits under DCO 1.1, and follow ecosystem terminology and dual-track licensing rules.

## Code of Conduct & Security

- All participants are expected to follow our [Code of Conduct](./CODE_OF_CONDUCT.md) (enforcement contact: **jah.g@ifay.ai**).
- Do not open public issues or pull requests for undisclosed security vulnerabilities; report them privately per [SECURITY.md](./SECURITY.md).

## Contribution Workflow

We use a standard **fork -> branch -> pull request** workflow.

### 1. Fork and Clone

```bash
git clone https://github.com/<your-username>/Telepathy-Protocol.git
cd Telepathy-Protocol
git remote add upstream https://github.com/ChainMode/Telepathy-Protocol.git
```

### 2. Create a Topic Branch

Branch from `main` using a clear prefix (`feat/`, `fix/`, `docs/`, `schema/`, `refactor/`, `test/`, `chore/`):

```bash
git checkout -b feat/shared-context-lifecycle
```

### 3. Verify Changes & Open a Pull Request

Run the zero-dependency `@ifay/tp-sdk` test and lint suites locally, sign off your commits (`git commit -s`), push your branch, and open a Pull Request against `main` using the [PR template](./.github/pull-request-template.md).

## Development Setup & Verification

`@ifay/tp-sdk` is a zero-runtime-dependency Node.js ESM reference SDK built on `node:crypto`.

### Prerequisites

- Node.js `>= 20.0.0`

### Verification Commands

```bash
# Run full unit, property-convergence, bridge, and 21-vector conformance suite
npm test

# Syntax-check all ESM SDK modules
npm run lint
```

## Schema & Conformance Vector Discipline

- **Frozen `TP/1.0` Normative Baseline**: `schemas/tp-1.0.json`, `schema/2025-10-25/`, and `vectors/tp-1.0-conformance.json` are **frozen** once released. Never mutate released `1.0` schemas in ways that break wire compatibility.
- **Additive Minor Evolution & Draft Sync**: Backward-compatible minor evolutions MUST be published as new versioned schema and vector files (for example `schemas/tp-1.1.json` and `vectors/tp-1.1-conformance.json`). When updating active draft mirrors under `schema/draft/` (`schema.json`, `schema.ts`, `schema.mdx`), update all three files together and record the change in [`schema/CHANGELOG.md`](./schema/CHANGELOG.md).
- **Scientific Honesty & Safety Gates**: Changes MUST preserve the normative three-layer cognitive architecture (`tier_3_structured_text_fallback` mandatory fallback), `ModelHomogeneityAttestation` gating on optional experimental latent frames, **Human Prime** mandate verification (`fp_authorization_ref`), **Host** terminal handoff gating (`cap_handoff_ref`), and explicit `LossMetadata` (`semantic_loss`) bridge disclosures.

## Ecosystem Terminology Rules

All specifications, schemas, SDK code, and translations MUST use positive canonical iFay terminology:

- **`Human Prime`** (`人类原型`): Exclusively denotes the natural person mapped and served by an `iFay`.
- **`Host`** (`宿主`): Strictly denotes a runtime terminal hardware device or client software application.
- **`Fay`** (`iFay` + `coFay`): Denotes an accountable digital avatar bound to a verifiable legal responsibility entity.
- **`GMChain`** (`公誉链`) & **`MeriToken`** (`美誉值` / `Merit Unit`): Denotes the ecosystem's strictly non-monetary social contribution reputation metric.

## Commit Message Convention & DCO 1.1 Sign-Off

Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat`, `fix`, `docs`, `schema`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`, `revert`) with optional scopes (`spec`, `schema`, `sdk`, `blueprint`, `docs`, `i18n`).

Every commit MUST carry a **Developer Certificate of Origin v1.1 (DCO 1.1)** `Signed-off-by` trailer (`git commit -s`), certifying that you have the right to submit your contribution under https://developercertificate.org/ (no separate CLA required):

```text
feat(sdk): enforce semantic_loss metadata on MCP bridge translation

Signed-off-by: Your Legal Name <you@example.com>
```

## Code Review & Issue Labels

- At least **one maintainer** approval is required for code/documentation PRs, and **two maintainer** approvals for specification or schema evolutions.
- Common issue labels: `bug`, `feature`, `rfc`, `documentation`, `schema`, `translation`, `question`.

## Dual-Track Inbound = Outbound Licensing

By submitting a contribution (`Inbound = Outbound`), you agree that your work is distributed under this repository's dual-track license model (`Copyright (c) 2025-2026 ChainMode contributors`):

- **MIT License** ([`LICENSE`](./LICENSE)) for `@ifay/tp-sdk` reference code and tests (`src/`, `tests/`, `ref/`), machine-readable schemas (`schemas/`, `schema/`), and conformance test vectors (`vectors/`).
- **Creative Commons Attribution 4.0 International (`CC BY 4.0`)** ([`LICENSE-DOCS`](./LICENSE-DOCS)) for protocol specifications and architectural blueprint documents under `docs/`.

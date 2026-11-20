/**
 * TP 1.0 `tp-workspace` — Fay-to-Fay Shared Cognitive Space Engine, HTTP Server, Client & MCP/A2A Bridge
 *
 * Enables two Fay instances (`Fay A` and `Fay B`, e.g., two `iFay`s or an `iFay` + a
 * `project_collaborator` `coFay`) to establish a mutually authorized Shared Cognitive Space
 * over the normative 5-step TP/1.0 handshake containing:
 *   1. Shared memory slices (`memory_fragment` with per-Fay ACLs & LWW sync)
 *   2. Live shared view/document state tree with Optimistic Concurrency Control (OCC versioned
 *      patches + object-pointer annotations eliminating prompt-telephone ambiguity)
 *   3. Shared rule constraints enforced across all mutations and actions
 *   4. Delegated action permissions within Human Prime Faying Mandate bounds + instant in-band
 *      revocation + zero-payload-leak SHA-256 hash-chained `AuditChain`
 *   5. Automatic protocol negotiation & lossless/loss-disclosing translation across native
 *      `TP/1.0`, `MCP tool_call` / `resources`, and `A2A JSON-RPC 2.0`
 */

import crypto from "node:crypto";
import http from "node:http";
import {
  createTpError,
  sha256Digest,
  signEnvelope,
  verifyEnvelope,
} from "./envelope.mjs";
import { SessionStateMachine } from "./session.mjs";
import {
  AuditChain,
  CallbackCredentialRegistry,
  SharedContextManager,
  createResourceNotification,
  mergeCollaborativeResourcesLww,
} from "./shared-context.mjs";
import { GoalStateMachine } from "./goals.mjs";
import {
  a2aTaskCardToTpGoal,
  buildCapControlHandoff,
  mcpResourceToTpResource,
  tpGoalToA2ATaskCard,
  tpResourceToMcpResource,
  verifyFayingMandateBinding,
} from "./bridges.mjs";

function setByPointerPath(target, pathStr, value) {
  const parts = String(pathStr)
    .replace(/^\//, "")
    .split("/")
    .filter(Boolean);
  if (parts.length === 0) return value;
  let curr = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (typeof curr[key] !== "object" || curr[key] === null) {
      curr[key] = {};
    }
    curr = curr[key];
  }
  curr[parts[parts.length - 1]] = structuredClone(value);
  return target;
}

function deleteByPointerPath(target, pathStr) {
  const parts = String(pathStr)
    .replace(/^\//, "")
    .split("/")
    .filter(Boolean);
  if (parts.length === 0) return target;
  let curr = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (typeof curr[key] !== "object" || curr[key] === null) {
      return target;
    }
    curr = curr[key];
  }
  delete curr[parts[parts.length - 1]];
  return target;
}

function containsForbiddenKeysDeep(obj, forbiddenSet) {
  if (!obj || typeof obj !== "object") return null;
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const hit = containsForbiddenKeysDeep(item, forbiddenSet);
      if (hit) return hit;
    }
    return null;
  }
  for (const [k, v] of Object.entries(obj)) {
    if (forbiddenSet.has(k.toLowerCase())) return k;
    const nested = containsForbiddenKeysDeep(v, forbiddenSet);
    if (nested) return nested;
  }
  return null;
}

/**
 * Automatically negotiates the highest-fidelity collaboration protocol between two peers
 * and discloses whether translation is lossless (`native_tp`) or carries explicit `LossMetadata`.
 */
export function negotiatePeerBridgeMode({
  localProtocols = ["native_tp", "a2a_jsonrpc", "mcp_tool_call"],
  peerProtocols = ["native_tp"],
  sharedOntologyMatch = true,
} = {}) {
  const priority = ["native_tp", "a2a_jsonrpc", "mcp_tool_call"];
  const selected = priority.find(
    (p) => localProtocols.includes(p) && peerProtocols.includes(p)
  );
  if (!selected) {
    return {
      ok: false,
      error: createTpError(
        "TP-NEG001",
        "No mutually supported protocol across native_tp, a2a_jsonrpc, or mcp_tool_call."
      ),
    };
  }

  if (selected === "native_tp") {
    return {
      ok: true,
      selectedProtocol: "native_tp",
      communicationTier: sharedOntologyMatch
        ? "tier_1_native_tp"
        : "tier_3_structured_text_fallback",
      lossless: Boolean(sharedOntologyMatch),
      lossMetadata: sharedOntologyMatch
        ? null
        : {
            source_protocol: "TP/1.0",
            target_protocol: "TP/1.0-tier3",
            dropped_fields: [],
            degraded_semantics: [
              "Ontology mismatch downgraded explicit frame to structured_text_fallback.",
            ],
            attribution_preserved: true,
            reversible: true,
          },
    };
  }

  if (selected === "a2a_jsonrpc") {
    return {
      ok: true,
      selectedProtocol: "a2a_jsonrpc",
      communicationTier: "external_bridge",
      lossless: false,
      lossMetadata: {
        source_protocol: "TP/1.0",
        target_protocol: "a2a",
        dropped_fields: ["sub_goals", "context_ref"],
        degraded_semantics: [
          "TP SharedContext and sub-goal DAG projected into A2A TaskCard metadata extension.",
        ],
        attribution_preserved: true,
        reversible: true,
      },
    };
  }

  return {
    ok: true,
    selectedProtocol: "mcp_tool_call",
    communicationTier: "external_bridge",
    lossless: false,
    lossMetadata: {
      source_protocol: "TP/1.0",
      target_protocol: "mcp",
      dropped_fields: ["access_policy.requires_encryption"],
      degraded_semantics: [
        "TP bilateral cognitive space projected as stateless MCP tool_call / resource operations.",
      ],
      attribution_preserved: true,
      reversible: true,
    },
  };
}

export class TpWorkspaceEngine {
  constructor({ mandateRegistry = new Map() } = {}) {
    this.mandateRegistry =
      mandateRegistry instanceof Map
        ? mandateRegistry
        : new Map(Object.entries(mandateRegistry));
    this.sharedContextManager = new SharedContextManager();
    this.goalStateMachine = new GoalStateMachine(this.sharedContextManager);
    this.workspaces = new Map();
  }

  registerMandate(fpAuthorizationRef, mandateRecord) {
    this.mandateRegistry.set(fpAuthorizationRef, structuredClone(mandateRecord));
  }

  openWorkspace({
    workspaceId = `ws_${crypto.randomUUID().slice(0, 8)}`,
    fayA,
    fayB,
    initiatorOffer,
    responderOffer,
    initialViewTree = {},
    initialRules = [],
    nowIso = new Date().toISOString(),
  }) {
    if (this.workspaces.has(workspaceId)) {
      return {
        ok: false,
        error: createTpError("TP-CTX001", `Workspace "${workspaceId}" already exists.`),
      };
    }

    // Verify Faying Mandate bindings when mandates are registered
    for (const participant of [fayA, fayB]) {
      if (!participant?.identity || !participant?.profile) {
        return {
          ok: false,
          error: createTpError(
            "TP-ID002",
            "Both fayA and fayB require { identity, profile }."
          ),
        };
      }
      if (this.mandateRegistry.size > 0) {
        const mCheck = verifyFayingMandateBinding(
          participant.identity,
          this.mandateRegistry,
          undefined,
          nowIso
        );
        if (!mCheck.ok) return mCheck;
      }
    }

    const defaultOntology = {
      ontology_id: "ifay.shared_workspace.v1",
      version: "1.0",
      codebook_digest: sha256Digest("ifay.shared_workspace.v1"),
    };

    const offerA = initiatorOffer ?? {
      tp_version: "1.0",
      fay_id: fayA.identity.fay_id,
      crypto_suites: ["Ed25519"],
      transports: [{ protocol: "native_tp", version: "1.0" }],
      supported_ontologies: fayA.profile.supported_ontologies?.length
        ? fayA.profile.supported_ontologies
        : [defaultOntology],
    };
    const offerB = responderOffer ?? {
      tp_version: "1.0",
      fay_id: fayB.identity.fay_id,
      crypto_suites: ["Ed25519"],
      transports: [{ protocol: "native_tp", version: "1.0" }],
      supported_ontologies: fayB.profile.supported_ontologies?.length
        ? fayB.profile.supported_ontologies
        : [defaultOntology],
    };

    // Execute 5-Step TP Session Establishment
    const sessionSm = new SessionStateMachine({ startTimeMs: Date.parse(nowIso) });
    const s1 = sessionSm.completeNegotiation(offerA, offerB, Date.parse(nowIso), {
      now: nowIso,
    });
    if (!s1.ok) return s1;

    // Optional cryptographic proof envelope check if keys supplied
    if (fayA.privateKey && fayA.publicKeyB64) {
      const signedProof = signEnvelope(
        {
          tp_version: "1.0",
          message_id: crypto.randomUUID(),
          sender: fayA.identity,
          receiver: fayB.identity,
          timestamp: nowIso,
          message_type: "identity_proof",
          payload: { workspace_id: workspaceId, step: 2 },
        },
        fayA.privateKey
      );
      if (!signedProof.ok) return signedProof;
      const verifiedProof = verifyEnvelope(signedProof.envelope, fayA.publicKeyB64);
      if (!verifiedProof.ok) return verifiedProof;
    }

    const s2 = sessionSm.verifyIdentities(
      fayA.identity,
      fayB.identity,
      Date.parse(nowIso)
    );
    if (!s2.ok) return s2;

    const s3 = sessionSm.exchangeProfiles(
      fayA.profile,
      fayB.profile,
      Date.parse(nowIso)
    );
    if (!s3.ok) return s3;

    const contextId = `ctx_${workspaceId}`;
    const ctxCreate = this.sharedContextManager.createContext({
      contextId,
      participants: [fayA.identity, fayB.identity],
      mode: "collaborative_space",
      defaultPolicy: "read_write",
      nowIso,
    });
    if (!ctxCreate.ok) return ctxCreate;

    const ctxActivate = this.sharedContextManager.activateContext(contextId, nowIso);
    if (!ctxActivate.ok) return ctxActivate;

    const s4 = sessionSm.establishInitialContext(
      { context_id: contextId, state: "active" },
      Date.parse(nowIso)
    );
    if (!s4.ok) return s4;

    const s5 = sessionSm.markReady(Date.parse(nowIso));
    if (!s5.ok) return s5;

    const auditChain = new AuditChain();
    const credentialRegistry = new CallbackCredentialRegistry();

    const initialTreeClone = structuredClone(initialViewTree);
    const viewState = {
      revision: 0,
      updated_at: nowIso,
      last_actor_fay_id: fayA.identity.fay_id,
      state_digest: sha256Digest(initialTreeClone),
      tree: initialTreeClone,
      object_annotations: {},
      patch_history: [],
    };

    const workspace = {
      workspaceId,
      contextId,
      createdAt: nowIso,
      participants: new Map([
        [fayA.identity.fay_id, structuredClone(fayA.identity)],
        [fayB.identity.fay_id, structuredClone(fayB.identity)],
      ]),
      contract: sessionSm.contract,
      sessionState: sessionSm.state,
      memorySlices: new Map(),
      lwwReplicaState: {},
      viewState,
      rules: structuredClone(initialRules),
      credentialRegistry,
      actionHandlers: new Map(),
      auditChain,
    };

    // Mount initial view_state resource inside SharedContextManager
    const viewTreeBytes = Buffer.byteLength(JSON.stringify(initialTreeClone), "utf8");
    this.sharedContextManager.mountResource(
      contextId,
      {
        mount_point: "/view/root",
        owner_fay_id: fayA.identity.fay_id,
        resource: {
          resource_id: `res_view_${workspaceId}`,
          resource_type: "view_state",
          content_ref: {
            mode: "inline",
            data: initialTreeClone,
            size_bytes: viewTreeBytes,
            checksum: viewState.state_digest,
          },
          access_policy: {
            owner_fay_id: fayA.identity.fay_id,
            visibility: "shared",
            requires_encryption: false,
          },
          schema_ref: "https://ifay.ai/schemas/tp-shared-view-1.0.json",
          metadata: {
            created_at: nowIso,
            updated_at: nowIso,
            version: 0,
          },
        },
      },
      nowIso
    );

    auditChain.append({
      record_id: `aud_${workspaceId}_0`,
      timestamp: nowIso,
      event_type: "workspace_opened",
      actor_fay_id: fayA.identity.fay_id,
      ...(fayA.identity.human_prime_id
        ? { human_prime_id: fayA.identity.human_prime_id }
        : {}),
      context_id: contextId,
      payloadForDigestOnly: {
        workspace_id: workspaceId,
        peer_fay_id: fayB.identity.fay_id,
        contract_id: sessionSm.contract.contract_id,
      },
    });

    this.workspaces.set(workspaceId, workspace);
    return {
      ok: true,
      workspaceId,
      contextId,
      contract: sessionSm.contract,
      snapshot: this.getSnapshot(workspaceId).snapshot,
    };
  }

  #getWorkspaceAndParticipant(workspaceId, actorFayId) {
    const ws = this.workspaces.get(workspaceId);
    if (!ws) {
      return {
        ok: false,
        error: createTpError("TP-CTX001", `Unknown workspace "${workspaceId}".`),
      };
    }
    const actor = ws.participants.get(actorFayId);
    if (!actor) {
      return {
        ok: false,
        error: createTpError(
          "TP-ID002",
          `Fay "${actorFayId}" is not an authorized participant of workspace "${workspaceId}".`
        ),
      };
    }
    return { ok: true, ws, actor };
  }

  #evaluateRules(ws, candidatePayload, numericContext = {}) {
    for (const rule of ws.rules) {
      if (Array.isArray(rule.forbidden_keys) && rule.forbidden_keys.length > 0) {
        const forbiddenSet = new Set(rule.forbidden_keys.map((k) => k.toLowerCase()));
        const hit = containsForbiddenKeysDeep(candidatePayload, forbiddenSet);
        if (hit) {
          return {
            ok: false,
            ruleId: rule.rule_id,
            reason: `Shared rule "${rule.rule_id}" forbids field "${hit}" (${rule.description ?? "redline"}).`,
          };
        }
      }
      if (
        typeof rule.max_numeric_field === "string" &&
        typeof rule.max_value === "number"
      ) {
        const val =
          numericContext[rule.max_numeric_field] ??
          candidatePayload?.[rule.max_numeric_field];
        if (typeof val === "number" && val > rule.max_value) {
          return {
            ok: false,
            ruleId: rule.rule_id,
            reason: `Shared rule "${rule.rule_id}" violated: ${rule.max_numeric_field}=${val} exceeds max ${rule.max_value}.`,
          };
        }
      }
    }
    return { ok: true };
  }

  /**
   * Pillar 1: Mount or update a Shared Memory Slice inside the Shared Cognitive Space.
   */
  mountMemorySlice({
    workspaceId,
    actorFayId,
    sliceId,
    data,
    permissions,
    nowIso = new Date().toISOString(),
  }) {
    const check = this.#getWorkspaceAndParticipant(workspaceId, actorFayId);
    if (!check.ok) return check;
    const { ws, actor } = check;

    const ruleCheck = this.#evaluateRules(ws, data);
    if (!ruleCheck.ok) {
      ws.auditChain.append({
        record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
        timestamp: nowIso,
        event_type: "rule_violation_blocked",
        actor_fay_id: actorFayId,
        context_id: ws.contextId,
        payloadForDigestOnly: { sliceId, ruleId: ruleCheck.ruleId },
      });
      return {
        ok: false,
        error: createTpError("TP-RULE001", ruleCheck.reason, {
          rule_id: ruleCheck.ruleId,
        }),
      };
    }

    const mountPoint = `/memory/${sliceId}`;
    const existing = ws.memorySlices.get(sliceId);
    if (existing) {
      const writeCheck = this.sharedContextManager.checkAccess(
        ws.contextId,
        actorFayId,
        mountPoint,
        "write",
        nowIso
      );
      if (!writeCheck.ok) return writeCheck;
    }

    const serializedBytes = Buffer.byteLength(JSON.stringify(data ?? null), "utf8");
    const resourceId = `res_mem_${sliceId}`;
    const nextSyncVersion = (existing?.sync_version ?? 0) + 1;
    const resource = {
      resource_id: resourceId,
      resource_type: "memory_fragment",
      content_ref: {
        mode: "inline",
        content_type: "application/json",
        data: structuredClone(data),
        size_bytes: serializedBytes,
        checksum: sha256Digest(data),
      },
      access_policy: {
        owner_fay_id: existing?.owner_fay_id ?? actorFayId,
        visibility: "shared",
        requires_encryption: false,
      },
      schema_ref: "https://ifay.ai/schemas/tp-memory-slice-1.0.json",
      metadata: {
        created_at: existing?.created_at ?? nowIso,
        updated_at: nowIso,
        version: nextSyncVersion,
      },
    };

    const mountRes = this.sharedContextManager.mountResource(
      ws.contextId,
      {
        mount_point: mountPoint,
        owner_fay_id: resource.access_policy.owner_fay_id,
        permissions,
        resource,
      },
      nowIso
    );
    if (!mountRes.ok) return mountRes;

    const sliceEntry = {
      slice_id: sliceId,
      owner_fay_id: resource.access_policy.owner_fay_id,
      sync_version: nextSyncVersion,
      updated_at: nowIso,
      actor_fay_id: actorFayId,
      data: structuredClone(data),
      resource,
    };
    ws.memorySlices.set(sliceId, sliceEntry);
    ws.lwwReplicaState = mergeCollaborativeResourcesLww(ws.lwwReplicaState, {
      [sliceId]: {
        sync_version: nextSyncVersion,
        updated_at: nowIso,
        actor_fay_id: actorFayId,
        value: structuredClone(data),
      },
    });

    const notification = createResourceNotification({
      contextId: ws.contextId,
      resource,
      changeKind: existing ? "updated" : "mounted",
      syncVersion: nextSyncVersion,
      actorFayId,
      updatedAt: nowIso,
    });

    ws.auditChain.append({
      record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
      timestamp: nowIso,
      event_type: "memory_slice_mounted",
      actor_fay_id: actorFayId,
      ...(actor.human_prime_id ? { human_prime_id: actor.human_prime_id } : {}),
      context_id: ws.contextId,
      resource_id: resourceId,
      payload_digest: notification.content_digest,
    });

    return {
      ok: true,
      slice: structuredClone(sliceEntry),
      notification,
    };
  }

  /**
   * Pillar 2: Apply an Optimistic Concurrency Control (OCC) versioned patch + object-pointer
   * annotation to the live Shared View / Document State Tree.
   */
  applyViewPatch({
    workspaceId,
    actorFayId,
    baseRevision,
    operations = [],
    objectAnnotation = null,
    nowIso = new Date().toISOString(),
  }) {
    const check = this.#getWorkspaceAndParticipant(workspaceId, actorFayId);
    if (!check.ok) return check;
    const { ws, actor } = check;

    if (baseRevision !== ws.viewState.revision) {
      return {
        ok: false,
        error: createTpError(
          "TP-OCC001",
          `Optimistic concurrency conflict: expected baseRevision ${ws.viewState.revision}, received ${baseRevision}.`,
          {
            current_revision: ws.viewState.revision,
            current_state_digest: ws.viewState.state_digest,
            authoritative_tree: structuredClone(ws.viewState.tree),
          }
        ),
      };
    }

    const candidateTree = structuredClone(ws.viewState.tree);
    for (const op of operations) {
      if (!op || typeof op.op !== "string" || typeof op.path !== "string") {
        return {
          ok: false,
          error: createTpError("TP-RES001", "Invalid view patch operation."),
        };
      }
      if (op.op === "set" || op.op === "replace" || op.op === "add") {
        setByPointerPath(candidateTree, op.path, op.value);
      } else if (op.op === "remove" || op.op === "delete") {
        deleteByPointerPath(candidateTree, op.path);
      } else {
        return {
          ok: false,
          error: createTpError("TP-RES001", `Unsupported patch op "${op.op}".`),
        };
      }
    }

    const ruleCheck = this.#evaluateRules(ws, candidateTree);
    if (!ruleCheck.ok) {
      ws.auditChain.append({
        record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
        timestamp: nowIso,
        event_type: "rule_violation_blocked",
        actor_fay_id: actorFayId,
        context_id: ws.contextId,
        payloadForDigestOnly: { baseRevision, ruleId: ruleCheck.ruleId },
      });
      return {
        ok: false,
        error: createTpError("TP-RULE001", ruleCheck.reason, {
          rule_id: ruleCheck.ruleId,
        }),
      };
    }

    const nextRevision = ws.viewState.revision + 1;
    const nextDigest = sha256Digest(candidateTree);
    ws.viewState.tree = candidateTree;
    ws.viewState.revision = nextRevision;
    ws.viewState.updated_at = nowIso;
    ws.viewState.last_actor_fay_id = actorFayId;
    ws.viewState.state_digest = nextDigest;

    if (objectAnnotation && typeof objectAnnotation.pointer_id === "string") {
      ws.viewState.object_annotations[objectAnnotation.pointer_id] = {
        ...structuredClone(objectAnnotation),
        annotated_by: actorFayId,
        bound_revision: nextRevision,
        bound_state_digest: nextDigest,
      };
    }

    ws.viewState.patch_history.push({
      revision: nextRevision,
      actor_fay_id: actorFayId,
      timestamp: nowIso,
      operation_count: operations.length,
      state_digest: nextDigest,
      ...(objectAnnotation?.pointer_id
        ? { pointer_id: objectAnnotation.pointer_id }
        : {}),
    });

    // Keep mounted `/view/root` resource synchronized
    this.sharedContextManager.mountResource(
      ws.contextId,
      {
        mount_point: "/view/root",
        owner_fay_id: actorFayId,
        resource: {
          resource_id: `res_view_${workspaceId}`,
          resource_type: "view_state",
          content_ref: {
            mode: "inline",
            content_type: "application/json",
            data: structuredClone(candidateTree),
            size_bytes: Buffer.byteLength(JSON.stringify(candidateTree), "utf8"),
            checksum: nextDigest,
          },
          access_policy: {
            owner_fay_id: actorFayId,
            visibility: "shared",
            requires_encryption: false,
          },
          schema_ref: "https://ifay.ai/schemas/tp-shared-view-1.0.json",
          metadata: {
            created_at: ws.createdAt,
            updated_at: nowIso,
            version: nextRevision,
          },
        },
      },
      nowIso
    );

    ws.auditChain.append({
      record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
      timestamp: nowIso,
      event_type: "view_tree_patched",
      actor_fay_id: actorFayId,
      ...(actor.human_prime_id ? { human_prime_id: actor.human_prime_id } : {}),
      context_id: ws.contextId,
      resource_id: `res_view_${workspaceId}`,
      payload_digest: nextDigest,
    });

    return {
      ok: true,
      revision: nextRevision,
      stateDigest: nextDigest,
      tree: structuredClone(ws.viewState.tree),
      objectAnnotations: structuredClone(ws.viewState.object_annotations),
    };
  }

  /**
   * Pillar 3: Bind or append Shared Rule Constraints to the workspace.
   */
  addSharedRule({
    workspaceId,
    actorFayId,
    rule,
    nowIso = new Date().toISOString(),
  }) {
    const check = this.#getWorkspaceAndParticipant(workspaceId, actorFayId);
    if (!check.ok) return check;
    const { ws, actor } = check;

    if (!rule || typeof rule.rule_id !== "string") {
      return {
        ok: false,
        error: createTpError("TP-RULE001", "Shared rule requires rule_id."),
      };
    }

    const existingIdx = ws.rules.findIndex((r) => r.rule_id === rule.rule_id);
    if (existingIdx >= 0) {
      ws.rules[existingIdx] = structuredClone(rule);
    } else {
      ws.rules.push(structuredClone(rule));
    }

    ws.auditChain.append({
      record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
      timestamp: nowIso,
      event_type: "shared_rule_bound",
      actor_fay_id: actorFayId,
      ...(actor.human_prime_id ? { human_prime_id: actor.human_prime_id } : {}),
      context_id: ws.contextId,
      payloadForDigestOnly: rule,
    });

    return { ok: true, rules: structuredClone(ws.rules) };
  }

  registerActionHandler(workspaceId, actionKey, fn) {
    const ws = this.workspaces.get(workspaceId);
    if (!ws) throw new Error(`Unknown workspace: ${workspaceId}`);
    ws.actionHandlers.set(actionKey, fn);
  }

  /**
   * Pillar 4a: Issue a Delegated Action Permission (`CallbackCredential`) within Human Prime bounds.
   */
  delegateActionPermission({
    workspaceId,
    issuerFayId,
    granteeFayId,
    credentialId = `cred_${crypto.randomUUID().slice(0, 8)}`,
    resources,
    operations,
    maxParameterBounds = {},
    expiration = new Date(Date.now() + 3_600_000).toISOString(),
    nowIso = new Date().toISOString(),
  }) {
    const issuerCheck = this.#getWorkspaceAndParticipant(workspaceId, issuerFayId);
    if (!issuerCheck.ok) return issuerCheck;
    const granteeCheck = this.#getWorkspaceAndParticipant(workspaceId, granteeFayId);
    if (!granteeCheck.ok) return granteeCheck;

    const { ws, actor: issuer } = issuerCheck;
    if (this.mandateRegistry.size > 0) {
      for (const op of operations) {
        const mOk = verifyFayingMandateBinding(
          issuer,
          this.mandateRegistry,
          op,
          nowIso
        );
        if (!mOk.ok) return mOk;
      }
    }

    const credential = {
      credential_id: credentialId,
      issuer_fay_id: issuerFayId,
      grantee_fay_id: granteeFayId,
      scope: {
        resources: [...resources],
        operations: [...operations],
        max_parameter_bounds: structuredClone(maxParameterBounds),
      },
      expiration,
      encrypted_token: Buffer.from(
        sha256Digest({ credentialId, issuerFayId, granteeFayId, nowIso })
      ).toString("base64"),
    };

    const issued = ws.credentialRegistry.issueCredential(credential);
    if (!issued.ok) return issued;

    ws.auditChain.append({
      record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
      timestamp: nowIso,
      event_type: "action_permission_delegated",
      actor_fay_id: issuerFayId,
      ...(issuer.human_prime_id ? { human_prime_id: issuer.human_prime_id } : {}),
      context_id: ws.contextId,
      credential_id: credentialId,
      payloadForDigestOnly: {
        grantee_fay_id: granteeFayId,
        resources,
        operations,
        maxParameterBounds,
      },
    });

    return { ok: true, credential: issued.credential };
  }

  /**
   * Pillar 4b: Execute a Delegated Action within Human Prime bounds & Shared Rule Constraints.
   */
  async executeDelegatedAction({
    workspaceId,
    actorFayId,
    credentialId,
    resourceId,
    operation,
    parameters = {},
    hostDeviceId = undefined,
    nowIso = new Date().toISOString(),
  }) {
    const check = this.#getWorkspaceAndParticipant(workspaceId, actorFayId);
    if (!check.ok) return check;
    const { ws, actor } = check;

    const credCheck = ws.credentialRegistry.verifyAccess(
      credentialId,
      resourceId,
      operation,
      nowIso
    );
    if (!credCheck.ok) {
      ws.auditChain.append({
        record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
        timestamp: nowIso,
        event_type: "delegated_action_denied",
        actor_fay_id: actorFayId,
        context_id: ws.contextId,
        credential_id: credentialId,
        resource_id: resourceId,
        payloadForDigestOnly: { operation, error_code: credCheck.error.error_code },
      });
      return credCheck;
    }

    const cred = credCheck.credential;
    if (cred.grantee_fay_id && cred.grantee_fay_id !== actorFayId) {
      return {
        ok: false,
        error: createTpError(
          "TP-C003",
          `Credential "${credentialId}" was granted to "${cred.grantee_fay_id}", not "${actorFayId}".`
        ),
      };
    }

    // Enforce parameter ceiling bounds declared on Human Prime delegation
    for (const [paramKey, maxVal] of Object.entries(
      cred.scope.max_parameter_bounds ?? {}
    )) {
      const actualVal = parameters?.[paramKey];
      if (typeof maxVal === "number" && typeof actualVal === "number" && actualVal > maxVal) {
        return {
          ok: false,
          error: createTpError(
            "TP-FP001",
            `Parameter "${paramKey}" (${actualVal}) exceeds Human Prime delegated bound (${maxVal}).`
          ),
        };
      }
    }

    const ruleCheck = this.#evaluateRules(ws, parameters, parameters);
    if (!ruleCheck.ok) {
      return {
        ok: false,
        error: createTpError("TP-RULE001", ruleCheck.reason, {
          rule_id: ruleCheck.ruleId,
        }),
      };
    }

    let capHandoff = null;
    if (hostDeviceId) {
      const syntheticGoal = {
        goal_id: `goal_act_${crypto.randomUUID().slice(0, 8)}`,
        parameters: { values: parameters },
      };
      const capRes = buildCapControlHandoff({
        goal: syntheticGoal,
        sender: actor,
        hostDeviceId,
        capabilityId: `${resourceId}:${operation}`,
        accessMode: operation,
      });
      if (!capRes.ok) return capRes;
      capHandoff = {
        capHandoffRef: capRes.capHandoffRef,
        capRequest: capRes.capRequest,
      };
    }

    const handler =
      ws.actionHandlers.get(`${resourceId}:${operation}`) ??
      ws.actionHandlers.get(operation);
    const output = handler
      ? await handler({ parameters, actorFayId, resourceId, operation })
      : {
          executed: true,
          resource_id: resourceId,
          operation,
          accepted_parameters: structuredClone(parameters),
        };

    ws.auditChain.append({
      record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
      timestamp: nowIso,
      event_type: "delegated_action_executed",
      actor_fay_id: actorFayId,
      ...(actor.human_prime_id ? { human_prime_id: actor.human_prime_id } : {}),
      context_id: ws.contextId,
      credential_id: credentialId,
      resource_id: resourceId,
      payloadForDigestOnly: { operation, parameters, output },
    });

    return {
      ok: true,
      output,
      ...(capHandoff ? { capHandoff } : {}),
    };
  }

  revokeDelegatedCredential({
    workspaceId,
    issuerFayId,
    credentialId,
    reason = "Revoked by Human Prime / issuer Fay",
    nowIso = new Date().toISOString(),
  }) {
    const check = this.#getWorkspaceAndParticipant(workspaceId, issuerFayId);
    if (!check.ok) return check;
    const { ws, actor } = check;

    const rev = ws.credentialRegistry.processCredentialRevokeMessage({
      credential_id: credentialId,
      issuer_fay_id: issuerFayId,
      revoked_at: nowIso,
      reason,
    });
    if (!rev.ok) return rev;

    ws.auditChain.append({
      record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
      timestamp: nowIso,
      event_type: "credential_revoked",
      actor_fay_id: issuerFayId,
      ...(actor.human_prime_id ? { human_prime_id: actor.human_prime_id } : {}),
      context_id: ws.contextId,
      credential_id: credentialId,
      payloadForDigestOnly: { reason },
    });

    return { ok: true };
  }

  /**
   * Bridge 1: MCP (`tools/list`, `tools/call`, `resources/read`, `resources/import`) <-> Shared Cognitive Space
   * with explicit `LossMetadata`.
   */
  handleMcpBridgeCall({
    workspaceId,
    actorFayId,
    method,
    params = {},
    nowIso = new Date().toISOString(),
  }) {
    const check = this.#getWorkspaceAndParticipant(workspaceId, actorFayId);
    if (!check.ok) return check;
    const { ws, actor } = check;

    if (method === "tools/list") {
      return {
        ok: true,
        mcpResult: {
          tools: [
            {
              name: "tp_workspace_get_snapshot",
              description: "Read Shared Cognitive Space view tree, memory slices, and rules",
              inputSchema: { type: "object", properties: {} },
            },
            {
              name: "tp_workspace_patch_view",
              description: "Apply an OCC versioned patch to the shared view state tree",
              inputSchema: {
                type: "object",
                required: ["baseRevision", "operations"],
                properties: {
                  baseRevision: { type: "number" },
                  operations: { type: "array" },
                  objectAnnotation: { type: "object" },
                },
              },
            },
            {
              name: "tp_workspace_mount_memory",
              description: "Mount or update a shared memory slice",
              inputSchema: {
                type: "object",
                required: ["sliceId", "data"],
                properties: {
                  sliceId: { type: "string" },
                  data: { type: "object" },
                },
              },
            },
          ],
        },
        lossMetadata: {
          source_protocol: "TP/1.0",
          target_protocol: "mcp",
          dropped_fields: ["protocol_contract.shared_ontology"],
          degraded_semantics: [
            "TP stateful cognitive operations projected as stateless MCP tools.",
          ],
          attribution_preserved: true,
          reversible: true,
        },
      };
    }

    if (method === "resources/read") {
      const ctx = this.sharedContextManager.getContext(ws.contextId);
      const mounted = ctx.mounted_resources.find(
        (m) => m.mount_point === (params.mountPoint ?? "/view/root")
      );
      if (!mounted) {
        return {
          ok: false,
          error: createTpError("TP-RES001", "Requested mountPoint not found."),
        };
      }
      const translated = tpResourceToMcpResource(mounted.resource, actor);
      if (!translated.ok) return translated;
      ws.auditChain.append({
        record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
        timestamp: nowIso,
        event_type: "mcp_bridge_resource_read",
        actor_fay_id: actorFayId,
        context_id: ws.contextId,
        resource_id: mounted.resource.resource_id,
        payloadForDigestOnly: { lossMetadata: translated.lossMetadata },
      });
      return {
        ok: true,
        mcpResult: { contents: [translated.mcpResource] },
        lossMetadata: translated.lossMetadata,
      };
    }

    if (method === "resources/import") {
      const imported = mcpResourceToTpResource(params.mcpResource, actorFayId, nowIso);
      if (!imported.ok) return imported;
      const sliceId = params.sliceId ?? imported.resource.resource_id;
      const mountRes = this.mountMemorySlice({
        workspaceId,
        actorFayId,
        sliceId,
        data: imported.resource.content_ref.data ?? {
          uri: imported.resource.content_ref.uri,
        },
        nowIso,
      });
      if (!mountRes.ok) return mountRes;
      return {
        ok: true,
        mcpResult: { slice_id: sliceId, sync_version: mountRes.slice.sync_version },
        lossMetadata: imported.lossMetadata,
      };
    }

    if (method === "tools/call") {
      const toolName = params.name;
      const args = params.arguments ?? {};
      const lossMetadata = {
        source_protocol: "mcp",
        target_protocol: "TP/1.0",
        dropped_fields: [],
        degraded_semantics: [
          "MCP tool_call wrapped into authenticated TP Shared Cognitive Space mutation.",
        ],
        attribution_preserved: true,
        reversible: true,
      };

      if (toolName === "tp_workspace_get_snapshot") {
        const snap = this.getSnapshot(workspaceId).snapshot;
        return {
          ok: true,
          mcpResult: {
            content: [{ type: "text", text: JSON.stringify(snap) }],
            structuredContent: snap,
            _meta: { tp_loss_metadata: lossMetadata },
          },
          lossMetadata,
        };
      }

      if (toolName === "tp_workspace_patch_view") {
        const patchRes = this.applyViewPatch({
          workspaceId,
          actorFayId,
          baseRevision: args.baseRevision,
          operations: args.operations ?? [],
          objectAnnotation: args.objectAnnotation ?? null,
          nowIso,
        });
        if (!patchRes.ok) return patchRes;
        return {
          ok: true,
          mcpResult: {
            content: [{ type: "text", text: JSON.stringify(patchRes) }],
            structuredContent: patchRes,
            _meta: { tp_loss_metadata: lossMetadata },
          },
          lossMetadata,
        };
      }

      if (toolName === "tp_workspace_mount_memory") {
        const memRes = this.mountMemorySlice({
          workspaceId,
          actorFayId,
          sliceId: args.sliceId,
          data: args.data,
          nowIso,
        });
        if (!memRes.ok) return memRes;
        return {
          ok: true,
          mcpResult: {
            content: [{ type: "text", text: JSON.stringify(memRes.notification) }],
            structuredContent: memRes.notification,
            _meta: { tp_loss_metadata: lossMetadata },
          },
          lossMetadata,
        };
      }

      return {
        ok: false,
        error: createTpError("TP-TRA020", `Unknown MCP bridge tool "${toolName}".`),
      };
    }

    return {
      ok: false,
      error: createTpError("TP-TRA020", `Unsupported MCP bridge method "${method}".`),
    };
  }

  /**
   * Bridge 2: A2A JSON-RPC 2.0 (`tasks/send`) <-> TP GoalStateMachine + Shared Cognitive Space
   * with explicit `LossMetadata`.
   */
  handleA2aJsonRpc({
    workspaceId,
    actorFayId,
    jsonRpcRequest,
    nowIso = new Date().toISOString(),
  }) {
    const check = this.#getWorkspaceAndParticipant(workspaceId, actorFayId);
    if (!check.ok) return check;
    const { ws, actor } = check;

    if (
      !jsonRpcRequest ||
      jsonRpcRequest.jsonrpc !== "2.0" ||
      jsonRpcRequest.method !== "tasks/send" ||
      !jsonRpcRequest.params
    ) {
      return {
        ok: false,
        error: createTpError(
          "TP-TRA010",
          "Expected A2A JSON-RPC 2.0 request with method 'tasks/send'."
        ),
      };
    }

    const inbound = a2aTaskCardToTpGoal(jsonRpcRequest.params, ws.contextId);
    if (!inbound.ok) return inbound;

    const ruleCheck = this.#evaluateRules(
      ws,
      inbound.goal.parameters?.values ?? {},
      inbound.goal.parameters?.values ?? {}
    );
    if (!ruleCheck.ok) {
      return {
        ok: false,
        error: createTpError("TP-RULE001", ruleCheck.reason, {
          rule_id: ruleCheck.ruleId,
        }),
      };
    }

    const proposed = this.goalStateMachine.proposeGoal(inbound.goal, nowIso);
    if (!proposed.ok) return proposed;
    this.goalStateMachine.acceptGoal(inbound.goal.goal_id);
    this.goalStateMachine.startExecution(inbound.goal.goal_id);

    const output = {
      workspace_id: workspaceId,
      context_id: ws.contextId,
      view_revision: ws.viewState.revision,
      view_state_digest: ws.viewState.state_digest,
      accepted_input: inbound.goal.parameters.values,
    };
    const completed = this.goalStateMachine.completeGoal(inbound.goal.goal_id, output);
    if (!completed.ok) return completed;

    const outbound = tpGoalToA2ATaskCard(completed.goal, actor, inbound.traceInfo);
    if (!outbound.ok) return outbound;

    ws.auditChain.append({
      record_id: `aud_${workspaceId}_${ws.auditChain.records.length}`,
      timestamp: nowIso,
      event_type: "a2a_bridge_goal_completed",
      actor_fay_id: actorFayId,
      ...(actor.human_prime_id ? { human_prime_id: actor.human_prime_id } : {}),
      context_id: ws.contextId,
      payloadForDigestOnly: {
        goal_id: completed.goal.goal_id,
        inboundLoss: inbound.lossMetadata,
        outboundLoss: outbound.lossMetadata,
      },
    });

    return {
      ok: true,
      jsonRpcResponse: {
        jsonrpc: "2.0",
        id: jsonRpcRequest.id,
        result: {
          ...outbound.taskCard,
          output,
          loss_metadata: outbound.lossMetadata,
        },
      },
      inboundLossMetadata: inbound.lossMetadata,
      outboundLossMetadata: outbound.lossMetadata,
    };
  }

  getSnapshot(workspaceId) {
    const ws = this.workspaces.get(workspaceId);
    if (!ws) {
      return {
        ok: false,
        error: createTpError("TP-CTX001", `Unknown workspace "${workspaceId}".`),
      };
    }
    const auditIntegrity = ws.auditChain.verifyIntegrity();
    const memorySlices = {};
    for (const [k, v] of ws.memorySlices.entries()) {
      memorySlices[k] = {
        owner_fay_id: v.owner_fay_id,
        sync_version: v.sync_version,
        updated_at: v.updated_at,
        actor_fay_id: v.actor_fay_id,
        data: structuredClone(v.data),
      };
    }

    return {
      ok: true,
      snapshot: {
        workspaceId: ws.workspaceId,
        contextId: ws.contextId,
        sessionState: ws.sessionState,
        contract: structuredClone(ws.contract),
        participants: Array.from(ws.participants.keys()),
        memorySlices,
        viewState: {
          revision: ws.viewState.revision,
          updated_at: ws.viewState.updated_at,
          last_actor_fay_id: ws.viewState.last_actor_fay_id,
          state_digest: ws.viewState.state_digest,
          tree: structuredClone(ws.viewState.tree),
          object_annotations: structuredClone(ws.viewState.object_annotations),
        },
        rules: structuredClone(ws.rules),
        auditSummary: {
          verified: auditIntegrity.ok,
          recordCount: ws.auditChain.records.length,
          headRecordHash:
            ws.auditChain.records[ws.auditChain.records.length - 1]?.record_hash ?? null,
        },
      },
    };
  }
}

async function readHttpJson(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text.trim().length > 0 ? JSON.parse(text) : {};
}

function sendHttpJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "tp-version": "TP/1.0",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

/**
 * Zero-dependency `node:http` server exposing `TpWorkspaceEngine` over HTTP for
 * local `FayGer` dual-Fay collaboration or cross-host `Fay-to-Fay` cognitive spaces.
 */
export class TpWorkspaceHttpServer {
  constructor({ engine = new TpWorkspaceEngine(), host = "127.0.0.1", port = 0 } = {}) {
    this.engine = engine;
    this.host = host;
    this.port = port;
    this.server = null;
    this.origin = "";
  }

  async start() {
    if (this.server) return this.origin;
    this.server = http.createServer((req, res) => {
      void this.#handle(req, res);
    });
    await new Promise((resolvePromise, rejectPromise) => {
      this.server.once("error", rejectPromise);
      this.server.listen(this.port, this.host, () => resolvePromise());
    });
    const addr = this.server.address();
    this.origin = `http://${this.host}:${addr.port}`;
    return this.origin;
  }

  async stop() {
    if (!this.server) return;
    const srv = this.server;
    this.server = null;
    await new Promise((resolvePromise, rejectPromise) => {
      srv.close((err) => (err ? rejectPromise(err) : resolvePromise()));
    });
  }

  async #handle(req, res) {
    try {
      const url = new URL(req.url ?? "/", this.origin || "http://127.0.0.1");
      const method = req.method ?? "GET";

      if (method === "POST" && url.pathname === "/tp/workspaces/open") {
        const body = await readHttpJson(req);
        const out = this.engine.openWorkspace(body);
        sendHttpJson(res, out.ok ? 201 : 400, out);
        return;
      }

      const snapMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/snapshot$/);
      if (method === "GET" && snapMatch) {
        const out = this.engine.getSnapshot(decodeURIComponent(snapMatch[1]));
        sendHttpJson(res, out.ok ? 200 : 404, out);
        return;
      }

      const memMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/memory$/);
      if (method === "POST" && memMatch) {
        const body = await readHttpJson(req);
        const out = this.engine.mountMemorySlice({
          ...body,
          workspaceId: decodeURIComponent(memMatch[1]),
        });
        sendHttpJson(res, out.ok ? 200 : 400, out);
        return;
      }

      const patchMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/view\/patch$/);
      if (method === "POST" && patchMatch) {
        const body = await readHttpJson(req);
        const out = this.engine.applyViewPatch({
          ...body,
          workspaceId: decodeURIComponent(patchMatch[1]),
        });
        const status = out.ok
          ? 200
          : out.error?.error_code === "TP-OCC001"
            ? 409
            : 400;
        sendHttpJson(res, status, out);
        return;
      }

      const rulesMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/rules$/);
      if (method === "POST" && rulesMatch) {
        const body = await readHttpJson(req);
        const out = this.engine.addSharedRule({
          ...body,
          workspaceId: decodeURIComponent(rulesMatch[1]),
        });
        sendHttpJson(res, out.ok ? 200 : 400, out);
        return;
      }

      const delMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/actions\/delegate$/);
      if (method === "POST" && delMatch) {
        const body = await readHttpJson(req);
        const out = this.engine.delegateActionPermission({
          ...body,
          workspaceId: decodeURIComponent(delMatch[1]),
        });
        sendHttpJson(res, out.ok ? 200 : 400, out);
        return;
      }

      const execMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/actions\/execute$/);
      if (method === "POST" && execMatch) {
        const body = await readHttpJson(req);
        const out = await this.engine.executeDelegatedAction({
          ...body,
          workspaceId: decodeURIComponent(execMatch[1]),
        });
        sendHttpJson(res, out.ok ? 200 : 403, out);
        return;
      }

      const revMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/credentials\/revoke$/);
      if (method === "POST" && revMatch) {
        const body = await readHttpJson(req);
        const out = this.engine.revokeDelegatedCredential({
          ...body,
          workspaceId: decodeURIComponent(revMatch[1]),
        });
        sendHttpJson(res, out.ok ? 200 : 400, out);
        return;
      }

      const mcpMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/bridge\/mcp$/);
      if (method === "POST" && mcpMatch) {
        const body = await readHttpJson(req);
        const out = this.engine.handleMcpBridgeCall({
          ...body,
          workspaceId: decodeURIComponent(mcpMatch[1]),
        });
        sendHttpJson(res, out.ok ? 200 : 400, out);
        return;
      }

      const a2aMatch = url.pathname.match(/^\/tp\/workspaces\/([^/]+)\/bridge\/a2a$/);
      if (method === "POST" && a2aMatch) {
        const body = await readHttpJson(req);
        const out = this.engine.handleA2aJsonRpc({
          ...body,
          workspaceId: decodeURIComponent(a2aMatch[1]),
        });
        sendHttpJson(res, out.ok ? 200 : 400, out);
        return;
      }

      sendHttpJson(
        res,
        404,
        { ok: false, error: createTpError("TP-ENV002", `Unknown route ${url.pathname}`) }
      );
    } catch (err) {
      sendHttpJson(res, 500, {
        ok: false,
        error: createTpError("TP-ENV001", err.message),
      });
    }
  }
}

/**
 * Lightweight HTTP Client for `Fay A` and `Fay B` to collaborate over `TpWorkspaceHttpServer`.
 */
export class TpWorkspaceClient {
  constructor({ baseUrl, actorFayId }) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.actorFayId = actorFayId;
  }

  async #post(path, payload) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    return { status: res.status, ...(await res.json()) };
  }

  async openWorkspace(params) {
    return this.#post("/tp/workspaces/open", params);
  }

  async getSnapshot(workspaceId) {
    const res = await fetch(
      `${this.baseUrl}/tp/workspaces/${encodeURIComponent(workspaceId)}/snapshot`
    );
    return { status: res.status, ...(await res.json()) };
  }

  async mountMemorySlice(workspaceId, { sliceId, data, permissions }) {
    return this.#post(
      `/tp/workspaces/${encodeURIComponent(workspaceId)}/memory`,
      { actorFayId: this.actorFayId, sliceId, data, permissions }
    );
  }

  async applyViewPatch(workspaceId, { baseRevision, operations, objectAnnotation }) {
    return this.#post(
      `/tp/workspaces/${encodeURIComponent(workspaceId)}/view/patch`,
      {
        actorFayId: this.actorFayId,
        baseRevision,
        operations,
        objectAnnotation,
      }
    );
  }

  async delegateActionPermission(workspaceId, params) {
    return this.#post(
      `/tp/workspaces/${encodeURIComponent(workspaceId)}/actions/delegate`,
      { issuerFayId: this.actorFayId, ...params }
    );
  }

  async executeDelegatedAction(workspaceId, params) {
    return this.#post(
      `/tp/workspaces/${encodeURIComponent(workspaceId)}/actions/execute`,
      { actorFayId: this.actorFayId, ...params }
    );
  }

  async revokeCredential(workspaceId, credentialId, reason) {
    return this.#post(
      `/tp/workspaces/${encodeURIComponent(workspaceId)}/credentials/revoke`,
      { issuerFayId: this.actorFayId, credentialId, reason }
    );
  }

  async callMcpBridge(workspaceId, method, params = {}) {
    return this.#post(
      `/tp/workspaces/${encodeURIComponent(workspaceId)}/bridge/mcp`,
      { actorFayId: this.actorFayId, method, params }
    );
  }

  async callA2aJsonRpc(workspaceId, jsonRpcRequest) {
    return this.#post(
      `/tp/workspaces/${encodeURIComponent(workspaceId)}/bridge/a2a`,
      { actorFayId: this.actorFayId, jsonRpcRequest }
    );
  }
}

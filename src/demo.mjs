/**
 * Live E2E Demo for `tp-workspace` (`Fay A` personal `iFay` <-> `Fay B` `project_collaborator` `coFay`).
 */

import { deriveEd25519KeyPairFromSeed, sha256Digest } from "./envelope.mjs";
import {
  TpWorkspaceClient,
  TpWorkspaceEngine,
  TpWorkspaceHttpServer,
  negotiatePeerBridgeMode,
} from "./workspace.mjs";

const SEED_FAY_A = "0101010101010101010101010101010101010101010101010101010101010101";
const SEED_FAY_B = "0202020202020202020202020202020202020202020202020202020202020202";

export function createDemoWorkspaceParticipants() {
  const keysA = deriveEd25519KeyPairFromSeed(SEED_FAY_A);
  const keysB = deriveEd25519KeyPairFromSeed(SEED_FAY_B);

  const sharedOntology = {
    ontology_id: "ifay.shared_workspace.v1",
    version: "1.0",
    codebook_digest: sha256Digest("ifay.shared_workspace.v1"),
  };

  const identityA = {
    fay_id: "ifay_alicearchitect234567",
    fay_type: "iFay",
    human_prime_id: "prime_alice_001",
    fp_authorization_ref: "fp_mandate_alice_ws_01",
    did: {
      method: "did:key",
      value: `did:key:z6MkAlice${keysA.publicKeyB64.slice(0, 12)}`,
      proof: {
        type: "Ed25519Signature2020",
        created: "2026-11-20T00:00:00Z",
        verification_method: "did:key:z6MkAlice#key-1",
        proof_value: keysA.publicKeyB64,
      },
    },
  };

  const identityB = {
    fay_id: "cofay_projectcollab234567",
    fay_type: "coFay",
    fp_authorization_ref: "fp_mandate_cofay_collab_01",
    did: {
      method: "did:web",
      value: "did:web:collab.ifay.ai",
      proof: {
        type: "Ed25519Signature2020",
        created: "2026-11-20T00:00:00Z",
        verification_method: "did:web:collab.ifay.ai#key-1",
        proof_value: keysB.publicKeyB64,
      },
    },
  };

  const makeParticipantProfile = (identity) => ({
    identity,
    capabilities: [
      {
        capability_id: "cap_architecture_coedit",
        name: "ArchitectureCoEditor",
        version: "1.0.0",
        input_schema: { type: "object" },
        output_schema: { type: "object" },
        access_level: "authorized",
      },
    ],
    supported_ontologies: [sharedOntology],
    supported_crypto_suites: ["Ed25519"],
    sharing_willingness: {
      shareable_resource_types: ["memory_fragment", "view_state", "environment_context"],
      preferred_mode: "collaborative_space",
      max_concurrent_contexts: 4,
    },
    status: {
      availability: "online",
      current_contexts: 0,
      last_active: "2026-11-20T00:00:00Z",
    },
    prime_authorization: {
      fp_authorization_ref: identity.fp_authorization_ref,
      authorized_resource_types: ["memory_fragment", "view_state", "environment_context"],
      authorized_operations: ["read", "write", "deploy_preview"],
      max_sharing_duration: "PT4H",
      restrictions: [],
    },
    conformance_level: "tp_full",
  });

  return {
    fayA: {
      identity: identityA,
      profile: makeParticipantProfile(identityA),
    },
    fayB: {
      identity: identityB,
      profile: makeParticipantProfile(identityB),
    },
    mandates: {
      fp_mandate_alice_ws_01: {
        fay_id: identityA.fay_id,
        human_prime_id: "prime_alice_001",
        allowed_operations: ["read", "write", "deploy_preview"],
        revoked: false,
      },
      fp_mandate_cofay_collab_01: {
        fay_id: identityB.fay_id,
        allowed_operations: ["read", "write", "deploy_preview"],
        revoked: false,
      },
    },
  };
}

export async function runTpWorkspaceDemo(options = {}) {
  const { fayA, fayB, mandates } = createDemoWorkspaceParticipants();
  const engine = new TpWorkspaceEngine({ mandateRegistry: mandates });
  const server = new TpWorkspaceHttpServer({ engine });
  const origin = await server.start();

  try {
    const clientA = new TpWorkspaceClient({
      baseUrl: origin,
      actorFayId: fayA.identity.fay_id,
    });
    const clientB = new TpWorkspaceClient({
      baseUrl: origin,
      actorFayId: fayB.identity.fay_id,
    });

    const workspaceId = "ws_release_plan_2026";
    const opened = await clientA.openWorkspace({
      workspaceId,
      fayA,
      fayB,
      initialViewTree: {
        documentTitle: "Batch 2 Release Checklist",
        milestones: {
          dtp: "verified",
          ssp: "verified",
          icp: "verified",
          tp: "in_review",
        },
      },
      initialRules: [
        {
          rule_id: "rule_no_raw_secrets",
          forbidden_keys: ["private_key", "raw_mnemonic", "ssn"],
          description: "Never place raw private keys or mnemonics into shared cognitive state",
        },
        {
          rule_id: "rule_budget_cap",
          max_numeric_field: "budget_usd",
          max_value: 500,
          description: "Preview compute budget must stay <= $500",
        },
      ],
    });

    engine.registerActionHandler(
      workspaceId,
      "preview_cluster:deploy_preview",
      async ({ parameters, actorFayId }) => ({
        deploymentId: "dep_preview_01",
        triggeredBy: actorFayId,
        budget_usd: parameters.budget_usd,
      })
    );

    // 1. Fay A mounts a shared memory slice
    await clientA.mountMemorySlice(workspaceId, {
      sliceId: "sprint_constraints",
      data: { targetLatencyMs: 50, zeroExternalDeps: true },
    });

    // 2. Fay B patches shared view tree (OCC revision 0 -> 1) with an object pointer annotation
    const patch1 = await clientB.applyViewPatch(workspaceId, {
      baseRevision: 0,
      operations: [{ op: "set", path: "/milestones/tp", value: "verified" }],
      objectAnnotation: {
        pointer_id: "ptr_tp_milestone",
        path: "/milestones/tp",
        note: "CoFay verified all 4 cognitive pillars",
      },
    });

    // 3. Stale revision (baseRevision: 0) is deterministically rejected with 409 TP-OCC001!
    const stalePatch = await clientA.applyViewPatch(workspaceId, {
      baseRevision: 0,
      operations: [{ op: "set", path: "/documentTitle", value: "Stale Overwrite" }],
    });

    // 4. Fay A delegates `deploy_preview` within Human Prime budget bound ($300) to Fay B
    const delegated = await clientA.delegateActionPermission(workspaceId, {
      granteeFayId: fayB.identity.fay_id,
      credentialId: "cred_preview_deploy_01",
      resources: ["preview_cluster"],
      operations: ["deploy_preview"],
      maxParameterBounds: { budget_usd: 300 },
    });

    const executedOk = await clientB.executeDelegatedAction(workspaceId, {
      credentialId: delegated.credential.credential_id,
      resourceId: "preview_cluster",
      operation: "deploy_preview",
      parameters: { budget_usd: 180 },
      hostDeviceId: "host_ci_runner_01",
    });

    // 5. Protocol negotiation + MCP & A2A bridges with LossMetadata
    const negotiationMcp = negotiatePeerBridgeMode({
      peerProtocols: ["mcp_tool_call"],
    });
    const mcpBridgeOut = await clientB.callMcpBridge(
      workspaceId,
      "resources/read",
      { mountPoint: "/view/root" }
    );
    const a2aBridgeOut = await clientB.callA2aJsonRpc(workspaceId, {
      jsonrpc: "2.0",
      id: "task_a2a_sync_01",
      method: "tasks/send",
      params: {
        id: "goal_a2a_verify_01",
        description: "Verify converged workspace digest from A2A peer",
        input: { budget_usd: 120 },
      },
    });

    const finalSnap = await clientA.getSnapshot(workspaceId);

    const report = {
      origin,
      workspaceId,
      communicationTier: opened.contract.communication_tier,
      convergedViewRevision: patch1.revision,
      convergedMilestones: finalSnap.snapshot.viewState.tree.milestones,
      sharedObjectPointers: Object.keys(
        finalSnap.snapshot.viewState.object_annotations
      ),
      stalePatchConflictCode: stalePatch.error?.error_code,
      delegatedActionCapHandoff: executedOk.capHandoff?.capHandoffRef,
      mcpBridgeLossDisclosed: Boolean(
        negotiationMcp.lossMetadata && mcpBridgeOut.lossMetadata
      ),
      a2aBridgeLossDisclosed: Boolean(a2aBridgeOut.outboundLossMetadata),
      auditChain: finalSnap.snapshot.auditSummary,
    };

    if (!options.silent) {
      console.log("=== TP 1.0 Shared Cognitive Workspace (Fay-to-Fay + MCP/A2A) Demo ===");
      console.log(JSON.stringify(report, null, 2));
    }
    return report;
  } finally {
    await server.stop();
  }
}

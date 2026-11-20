import test from "node:test";
import assert from "node:assert/strict";
import {
  TpWorkspaceClient,
  TpWorkspaceEngine,
  TpWorkspaceHttpServer,
  createDemoWorkspaceParticipants,
  negotiatePeerBridgeMode,
  runTpWorkspaceDemo,
} from "../src/index.mjs";

test("TpWorkspaceEngine opens Fay-to-Fay Shared Cognitive Space, enforces OCC view patches, shared rules, Human Prime bounds & instant revocation, and preserves zero-leak AuditChain", async () => {
  const { fayA, fayB, mandates } = createDemoWorkspaceParticipants();
  const engine = new TpWorkspaceEngine({ mandateRegistry: mandates });

  const opened = engine.openWorkspace({
    workspaceId: "ws_unit_01",
    fayA,
    fayB,
    initialViewTree: {
      doc: "Architecture Spec v1",
      sections: { auth: "draft", storage: "draft" },
    },
    initialRules: [
      {
        rule_id: "rule_no_raw_secrets",
        forbidden_keys: ["private_key", "raw_secret"],
        description: "No raw secrets in shared space",
      },
      {
        rule_id: "rule_spend_cap",
        max_numeric_field: "spend_usd",
        max_value: 250,
      },
    ],
  });
  assert.equal(opened.ok, true);
  assert.equal(opened.contract.communication_tier, "tier_1_native_tp");

  // 1. Shared Memory Slice: mount ok + forbidden key blocked by shared rule
  const memOk = engine.mountMemorySlice({
    workspaceId: "ws_unit_01",
    actorFayId: fayA.identity.fay_id,
    sliceId: "design_tokens",
    data: { theme: "solarized", gridPx: 8 },
  });
  assert.equal(memOk.ok, true);

  const memBlocked = engine.mountMemorySlice({
    workspaceId: "ws_unit_01",
    actorFayId: fayB.identity.fay_id,
    sliceId: "bad_slice",
    data: { private_key: "leaked" },
  });
  assert.equal(memBlocked.ok, false);
  assert.equal(memBlocked.error.error_code, "TP-RULE001");

  // 2. Shared View State Tree: OCC patch 0 -> 1 succeeds, stale baseRevision 0 rejected with TP-OCC001
  const patch1 = engine.applyViewPatch({
    workspaceId: "ws_unit_01",
    actorFayId: fayB.identity.fay_id,
    baseRevision: 0,
    operations: [{ op: "set", path: "/sections/auth", value: "approved" }],
    objectAnnotation: {
      pointer_id: "ptr_auth_section",
      path: "/sections/auth",
      comment: "Reviewed by coFay collaborator",
    },
  });
  assert.equal(patch1.ok, true);
  assert.equal(patch1.revision, 1);

  const stale = engine.applyViewPatch({
    workspaceId: "ws_unit_01",
    actorFayId: fayA.identity.fay_id,
    baseRevision: 0,
    operations: [{ op: "set", path: "/sections/storage", value: "stale" }],
  });
  assert.equal(stale.ok, false);
  assert.equal(stale.error.error_code, "TP-OCC001");
  assert.equal(stale.error.details.current_revision, 1);

  // Re-reading snapshot shows both Fays see identical state digest & annotated object
  const snapA = engine.getSnapshot("ws_unit_01").snapshot;
  assert.equal(snapA.viewState.revision, 1);
  assert.equal(snapA.viewState.tree.sections.auth, "approved");
  assert.ok(snapA.viewState.object_annotations.ptr_auth_section);

  // 3. Delegated Action Permissions within Human Prime bounds + instant revocation
  const del = engine.delegateActionPermission({
    workspaceId: "ws_unit_01",
    issuerFayId: fayA.identity.fay_id,
    granteeFayId: fayB.identity.fay_id,
    credentialId: "cred_act_1",
    resources: ["cloud_sandbox"],
    operations: ["deploy_preview"],
    maxParameterBounds: { spend_usd: 150 },
  });
  assert.equal(del.ok, true);

  // Over-bound spend_usd=200 (> 150 Human Prime bound) rejected with TP-FP001
  const overBound = await engine.executeDelegatedAction({
    workspaceId: "ws_unit_01",
    actorFayId: fayB.identity.fay_id,
    credentialId: "cred_act_1",
    resourceId: "cloud_sandbox",
    operation: "deploy_preview",
    parameters: { spend_usd: 200 },
  });
  assert.equal(overBound.ok, false);
  assert.equal(overBound.error.error_code, "TP-FP001");

  // Within-bound spend_usd=100 succeeds + emits CAP handoff when hostDeviceId provided
  const withinBound = await engine.executeDelegatedAction({
    workspaceId: "ws_unit_01",
    actorFayId: fayB.identity.fay_id,
    credentialId: "cred_act_1",
    resourceId: "cloud_sandbox",
    operation: "deploy_preview",
    parameters: { spend_usd: 100 },
    hostDeviceId: "host_devbox_01",
  });
  assert.equal(withinBound.ok, true);
  assert.match(withinBound.capHandoff.capHandoffRef, /^cap:\/\/1\.0\//);

  // Instant revocation blocks subsequent calls with TP-C002
  const rev = engine.revokeDelegatedCredential({
    workspaceId: "ws_unit_01",
    issuerFayId: fayA.identity.fay_id,
    credentialId: "cred_act_1",
    reason: "Task finished",
  });
  assert.equal(rev.ok, true);

  const afterRevoke = await engine.executeDelegatedAction({
    workspaceId: "ws_unit_01",
    actorFayId: fayB.identity.fay_id,
    credentialId: "cred_act_1",
    resourceId: "cloud_sandbox",
    operation: "deploy_preview",
    parameters: { spend_usd: 50 },
  });
  assert.equal(afterRevoke.ok, false);
  assert.equal(afterRevoke.error.error_code, "TP-C002");

  // AuditChain integrity verified & zero raw payload leakage
  const finalSnap = engine.getSnapshot("ws_unit_01").snapshot;
  assert.equal(finalSnap.auditSummary.verified, true);
  assert.ok(finalSnap.auditSummary.recordCount >= 6);
});

test("TpWorkspaceHttpServer + TpWorkspaceClient + MCP/A2A protocol negotiation & LossMetadata E2E", async () => {
  // Negotiator checks
  const nativeMode = negotiatePeerBridgeMode({ peerProtocols: ["native_tp"] });
  assert.equal(nativeMode.selectedProtocol, "native_tp");
  assert.equal(nativeMode.lossless, true);

  const a2aMode = negotiatePeerBridgeMode({ peerProtocols: ["a2a_jsonrpc"] });
  assert.equal(a2aMode.selectedProtocol, "a2a_jsonrpc");
  assert.equal(a2aMode.lossless, false);
  assert.equal(a2aMode.lossMetadata.target_protocol, "a2a");

  const mcpMode = negotiatePeerBridgeMode({ peerProtocols: ["mcp_tool_call"] });
  assert.equal(mcpMode.selectedProtocol, "mcp_tool_call");
  assert.equal(mcpMode.lossMetadata.target_protocol, "mcp");

  // Live HTTP E2E demo + MCP tools/call view patch
  const demoReport = await runTpWorkspaceDemo({ silent: true });
  assert.equal(demoReport.communicationTier, "tier_1_native_tp");
  assert.equal(demoReport.convergedViewRevision, 1);
  assert.equal(demoReport.stalePatchConflictCode, "TP-OCC001");
  assert.equal(demoReport.mcpBridgeLossDisclosed, true);
  assert.equal(demoReport.a2aBridgeLossDisclosed, true);
  assert.equal(demoReport.auditChain.verified, true);

  // Additional live MCP tools/call test against TpWorkspaceHttpServer
  const { fayA, fayB, mandates } = createDemoWorkspaceParticipants();
  const server = new TpWorkspaceHttpServer({
    engine: new TpWorkspaceEngine({ mandateRegistry: mandates }),
  });
  const origin = await server.start();
  try {
    const clientA = new TpWorkspaceClient({
      baseUrl: origin,
      actorFayId: fayA.identity.fay_id,
    });
    await clientA.openWorkspace({
      workspaceId: "ws_mcp_http",
      fayA,
      fayB,
      initialViewTree: { count: 1 },
    });
    const mcpPatch = await clientA.callMcpBridge("ws_mcp_http", "tools/call", {
      name: "tp_workspace_patch_view",
      arguments: {
        baseRevision: 0,
        operations: [{ op: "set", path: "/count", value: 2 }],
      },
    });
    assert.equal(mcpPatch.ok, true);
    assert.equal(mcpPatch.mcpResult.structuredContent.revision, 1);
    assert.equal(mcpPatch.lossMetadata.source_protocol, "mcp");
  } finally {
    await server.stop();
  }
});

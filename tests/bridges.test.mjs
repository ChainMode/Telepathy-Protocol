import test from "node:test";
import assert from "node:assert/strict";
import {
  verifyFayingMandateBinding,
  buildCapControlHandoff,
  bindDtpTunnelTransport,
  dtpFragmentToCognitiveResource,
  sspSkillDescriptorToCapability,
  matchCapabilitiesByExactSchema,
  icpCtxTurnToTpEnvelopePayload,
  tpGoalToA2ATaskCard,
  a2aTaskCardToTpGoal,
  tpResourceToMcpResource,
  mcpResourceToTpResource,
  encodePromptEmbeddingEnvelope
} from "../src/bridges.mjs";
import { deriveX25519KeyPairFromSeed } from "../src/shared-context.mjs";
import {
  ALICE_FAY_ID,
  BOB_FAY_ID,
  SEED_X25519_ALICE_HEX,
  SEED_X25519_BOB_HEX,
  makeAliceIdentity,
  makeBobIdentity
} from "./_fixtures.mjs";

test("FP & CAP bridges verify Faying Mandate binding and construct Host-device-scoped CAP control handoffs", () => {
  const mandateRegistry = new Map([
    [
      "fp_mandate_alice_2026_01",
      {
        mandate_id: "fp_mandate_alice_2026_01",
        human_prime_id: "prime_alice_001",
        fay_id: ALICE_FAY_ID,
        faying_grade: "G2",
        allowed_operations: ["read", "write", "consult", "device_control"],
        expires_at: "2026-12-31T23:59:59Z",
        revoked: false
      }
    ]
  ]);

  const alice = makeAliceIdentity();
  const fpOk = verifyFayingMandateBinding(
    alice,
    mandateRegistry,
    "device_control",
    "2026-11-16T00:00:00Z"
  );
  assert.equal(fpOk.ok, true);

  const fpMissing = verifyFayingMandateBinding(
    { ...alice, fp_authorization_ref: "fp_unknown" },
    mandateRegistry,
    "read",
    "2026-11-16T00:00:00Z"
  );
  assert.equal(fpMissing.ok, false);
  assert.equal(fpMissing.error.error_code, "TP-FP001");

  const goal = {
    goal_id: "goal_thermostat_01",
    goal_type: "execute",
    description: { summary: "Set smart thermostat to 22C", output_schema: { type: "object" } },
    parameters: { schema_ref: "https://ifay.ai/schemas/hvac.json", values: { target_celsius: 22 } },
    constraints: [],
    sub_goals: [],
    context_ref: "ctx_home_01",
    status: "accepted"
  };

  const capHandoff = buildCapControlHandoff({
    goal,
    sender: alice,
    hostDeviceId: "host_dev_livingroom_hvac_01",
    capabilityId: "hvac.temperature.set",
    accessMode: "write",
    criticality: "sensitive",
    fayingGrade: "G2"
  });
  assert.equal(capHandoff.ok, true);
  assert.equal(capHandoff.capRequest.protocol.name, "CAP");
  assert.equal(capHandoff.capRequest.protocol.version, "1.0");
  assert.equal(capHandoff.capRequest.host_device_id, "host_dev_livingroom_hvac_01");
  assert.equal(capHandoff.updatedGoal.cap_handoff_ref, capHandoff.capHandoffRef);
});

test("DTP & SSP bridges bind encrypted tunnel streams and perform exact SSP skill schema matching", () => {
  const dtpTransport = bindDtpTunnelTransport({
    tunnelId: "dtp_tun_9981",
    endpoint: "dtp://relay.ifay.example.org/dtp_tun_9981"
  });
  assert.equal(dtpTransport.ok, true);
  assert.equal(dtpTransport.transportMethod.protocol, "dtp_tunnel");

  const dtpRes = dtpFragmentToCognitiveResource({
    tunnelId: "dtp_tun_9981",
    streamId: 3,
    contentType: "application/vnd.ifay.graph+json",
    totalBytes: 262144,
    sha256Checksum: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    resourceId: "res_large_graph",
    ownerFayId: ALICE_FAY_ID,
    resourceType: "reasoning_engine",
    schemaRef: "https://ifay.ai/schemas/graph-v1.json",
    timestamp: "2026-11-16T00:00:00Z"
  });
  assert.equal(dtpRes.ok, true);
  assert.equal(dtpRes.resource.content_ref.mode, "dtp_tunnel");

  const sspCap = sspSkillDescriptorToCapability({
    skill_id: "ssp_skill_kyoto_rail_v1",
    name: "KyotoRailOptimizer",
    version: "1.2.0",
    input_schema: { type: "object", required: ["origin", "destination"], properties: { origin: { type: "string" }, destination: { type: "string" } } },
    output_schema: { type: "object", required: ["routes"], properties: { routes: { type: "array" } } },
    visibility: "authorized",
    tags: ["rail", "japan"]
  });
  assert.equal(sspCap.ssp_skill_ref, "ssp_skill_kyoto_rail_v1");

  const matches = matchCapabilitiesByExactSchema(
    [sspCap],
    { type: "object", properties: { destination: { type: "string" }, origin: { type: "string" } }, required: ["origin", "destination"] },
    { type: "object", required: ["routes"], properties: { routes: { type: "array" } } }
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].capability_id, "ssp_skill_kyoto_rail_v1");
});

test("ICP bridge preserves .ctx annotations and enforces encryption on secret/confidential turns", () => {
  const publicTurn = icpCtxTurnToTpEnvelopePayload({
    turn_id: "icp_turn_01",
    role: "ego_summary",
    privacy_tier: "shared",
    content: { summary: "Prefer morning trains" },
    annotations: { "@ctx.source": "ego_diary", "@ctx.confidence": 0.95 }
  });
  assert.equal(publicTurn.ok, true);
  assert.equal(publicTurn.icp_annotations["@ctx.source"], "ego_diary");

  // Secret ICP turn WITHOUT encryption keys MUST be rejected with TP-ICP001
  const unencryptedSecret = icpCtxTurnToTpEnvelopePayload({
    turn_id: "icp_turn_02",
    role: "private_memory",
    privacy_tier: "secret",
    content: { medical_note: "Allergy info" },
    annotations: { "@ctx.sensitivity": "high" }
  });
  assert.equal(unencryptedSecret.ok, false);
  assert.equal(unencryptedSecret.error.error_code, "TP-ICP001");

  const aliceX = deriveX25519KeyPairFromSeed(SEED_X25519_ALICE_HEX);
  const bobX = deriveX25519KeyPairFromSeed(SEED_X25519_BOB_HEX);
  const encryptedSecret = icpCtxTurnToTpEnvelopePayload(
    {
      turn_id: "icp_turn_02",
      role: "private_memory",
      privacy_tier: "secret",
      content: { medical_note: "Allergy info" },
      annotations: { "@ctx.sensitivity": "high" }
    },
    {
      senderPrivateKey: aliceX.privateKey,
      receiverPublicKeyB64: bobX.publicKeyB64,
      auditRef: "aud_icp_01"
    }
  );
  assert.equal(encryptedSecret.ok, true);
  assert.equal(encryptedSecret.payload.encryption_algorithm, "AES-256-GCM");
});

test("A2A, MCP, and Prompt Embedding bridges preserve attribution, guard SSRF/hops, and emit explicit LossMetadata", () => {
  const alice = makeAliceIdentity();
  const goal = {
    goal_id: "goal_a2a_01",
    goal_type: "query",
    description: {
      summary: "Query museum ticket availability",
      output_schema: { type: "object", required: ["available"], properties: { available: { type: "boolean" } } }
    },
    parameters: { schema_ref: "https://ifay.ai/schemas/museum.json", values: { date: "2026-11-20" } },
    constraints: [{ constraint_type: "deadline", value: "2026-11-16T01:00:00Z", required: true }],
    sub_goals: [{ sub_goal_id: "sg_check_slot", depends_on: [] }],
    context_ref: "ctx_museum_01",
    status: "proposed"
  };

  const a2aOut = tpGoalToA2ATaskCard(goal, alice, {
    original_protocol: "native_tp",
    original_message_id: "01933b4a-7c10-7000-8000-000000000099",
    hop_count: 1
  });
  assert.equal(a2aOut.ok, true);
  assert.equal(a2aOut.jsonRpcRequest.jsonrpc, "2.0");
  assert.equal(a2aOut.traceInfo.hop_count, 2);
  assert.equal(a2aOut.lossMetadata.attribution_preserved, true);
  assert.equal(a2aOut.lossMetadata.dropped_fields.includes("sub_goals"), true);

  const backToTp = a2aTaskCardToTpGoal(a2aOut.taskCard, "ctx_museum_01");
  assert.equal(backToTp.ok, true);
  assert.equal(backToTp.goal.goal_id, "goal_a2a_01");

  // Hop limit > 5 rejected with TP-TRA001
  const hopExceeded = tpGoalToA2ATaskCard(goal, alice, {
    original_protocol: "a2a",
    original_message_id: "msg_0",
    hop_count: 5
  });
  assert.equal(hopExceeded.ok, false);
  assert.equal(hopExceeded.error.error_code, "TP-TRA001");

  // MCP Resource round-trip + SSRF rejection on inbound MCP URI
  const tpRes = {
    resource_id: "res_mcp_01",
    resource_type: "environment_context",
    content_ref: {
      mode: "reference",
      uri: "https://weather.ifay.example.org/kyoto.json",
      content_type: "application/json",
      size_bytes: 512
    },
    access_policy: { owner_fay_id: ALICE_FAY_ID, visibility: "shared", requires_encryption: false },
    schema_ref: "https://ifay.ai/schemas/weather.json",
    metadata: { created_at: "2026-11-16T00:00:00Z", updated_at: "2026-11-16T00:00:00Z", version: 1 }
  };
  const mcpOut = tpResourceToMcpResource(tpRes, alice);
  assert.equal(mcpOut.ok, true);
  assert.equal(mcpOut.mcpResource.uri, "https://weather.ifay.example.org/kyoto.json");
  assert.equal(mcpOut.lossMetadata.target_protocol, "mcp");

  const mcpIn = mcpResourceToTpResource(mcpOut.mcpResource, ALICE_FAY_ID);
  assert.equal(mcpIn.ok, true);
  assert.equal(mcpIn.resource.resource_id, "res_mcp_01");

  const mcpSsrf = mcpResourceToTpResource(
    { uri: "http://127.0.0.1:8080/internal", name: "bad", mimeType: "text/plain" },
    BOB_FAY_ID
  );
  assert.equal(mcpSsrf.ok, false);
  assert.equal(mcpSsrf.error.error_code, "TP-RES002");

  // Prompt embedding blocks confidential unencrypted data with TP-TRA030
  const promptBlocked = encodePromptEmbeddingEnvelope(
    {
      tp_version: "1.0",
      message_id: "01933b4a-7c10-7000-8000-000000000111",
      sender: alice,
      receiver: makeBobIdentity(),
      timestamp: "2026-11-16T00:00:00Z",
      message_type: "cognitive_frame",
      payload: { summary: "secret" }
    },
    { containsConfidentialPlaintext: true }
  );
  assert.equal(promptBlocked.ok, false);
  assert.equal(promptBlocked.error.error_code, "TP-TRA030");
});

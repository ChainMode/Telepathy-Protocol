import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_INLINE_BYTES,
  validateSafeReferenceUri,
  validateCognitiveResource,
  createResourceNotification,
  validateResourceNotification,
  compareLwwTuple,
  mergeCollaborativeResourcesLww,
  SharedContextManager,
  deriveX25519KeyPairFromSeed,
  encryptPayload,
  decryptPayload,
  CallbackCredentialRegistry,
  AuditChain
} from "../src/shared-context.mjs";
import {
  ALICE_FAY_ID,
  BOB_FAY_ID,
  CAROL_FAY_ID,
  SEED_X25519_ALICE_HEX,
  SEED_X25519_BOB_HEX,
  makeAliceIdentity,
  makeBobIdentity
} from "./_fixtures.mjs";

test("validateSafeReferenceUri accepts public https:// URIs and rejects SSRF loopback/private/link-local/file URIs with TP-RES002", () => {
  assert.equal(validateSafeReferenceUri("https://cdn.ifay.example.org/resources/ctx-01.json").ok, true);
  assert.equal(validateSafeReferenceUri("https://[2606:4700:4700::1111]/blob.bin").ok, true);

  const rejectedUris = [
    "http://cdn.ifay.example.org/insecure.json",
    "file:///etc/passwd",
    "https://localhost/internal",
    "https://api.localhost/v1",
    "https://127.0.0.1/admin",
    "https://10.0.0.42/secret",
    "https://172.16.5.9/cluster",
    "https://172.31.255.255/cluster",
    "https://192.168.1.10/router",
    "https://169.254.169.254/latest/meta-data/",
    "https://100.64.1.2/cgnat",
    "https://[::1]/loopback6",
    "https://[fe80::1]/linklocal6",
    "https://[fd00::1234]/ula6",
    "https://[::ffff:127.0.0.1]/mapped-loopback",
    "https://user:pass@cdn.ifay.example.org/cred"
  ];

  for (const badUri of rejectedUris) {
    const res = validateSafeReferenceUri(badUri);
    assert.equal(res.ok, false, `Expected SSRF rejection for ${badUri}`);
    assert.equal(res.error.error_code, "TP-RES002");
  }
});

test("validateCognitiveResource enforces 64KB inline limit (TP-RES003) and SSRF reference guard (TP-RES002)", () => {
  const smallResource = {
    resource_id: "res_small_01",
    resource_type: "memory_fragment",
    content_ref: {
      mode: "inline",
      data: { preferences: ["window_seat", "quiet_car"] },
      size_bytes: 46
    },
    access_policy: {
      owner_fay_id: ALICE_FAY_ID,
      visibility: "shared",
      requires_encryption: false
    },
    schema_ref: "https://ifay.ai/schemas/memory-fragment-v1.json",
    metadata: {
      created_at: "2026-11-16T00:00:00Z",
      updated_at: "2026-11-16T00:00:00Z",
      version: 1
    }
  };
  assert.equal(validateCognitiveResource(smallResource).ok, true);

  const oversizedInline = {
    ...smallResource,
    resource_id: "res_oversized_02",
    content_ref: {
      mode: "inline",
      data: "x".repeat(MAX_INLINE_BYTES + 10),
      size_bytes: MAX_INLINE_BYTES + 12
    }
  };
  const overRes = validateCognitiveResource(oversizedInline);
  assert.equal(overRes.ok, false);
  assert.equal(overRes.error.error_code, "TP-RES003");

  const ssrfRefResource = {
    ...smallResource,
    resource_id: "res_ssrf_03",
    content_ref: {
      mode: "reference",
      uri: "https://169.254.169.254/latest/meta-data/iam",
      content_type: "application/json",
      size_bytes: 131072
    }
  };
  const ssrfRes = validateCognitiveResource(ssrfRefResource);
  assert.equal(ssrfRes.ok, false);
  assert.equal(ssrfRes.error.error_code, "TP-RES002");
});

test("createResourceNotification emits metadata-only digest and rejects raw content leakage (OQ-7)", () => {
  const resource = {
    resource_id: "res_01",
    resource_type: "view_state",
    content_ref: { mode: "inline", data: { active_tab: "hotels" }, size_bytes: 23 },
    access_policy: { owner_fay_id: ALICE_FAY_ID, visibility: "shared", requires_encryption: false },
    schema_ref: "https://ifay.ai/schemas/view-v1.json",
    metadata: { created_at: "2026-11-16T00:00:00Z", updated_at: "2026-11-16T00:01:00Z", version: 2 }
  };

  const notif = createResourceNotification({
    contextId: "ctx_01",
    resource,
    changeKind: "updated",
    syncVersion: 4,
    actorFayId: ALICE_FAY_ID,
    updatedAt: "2026-11-16T00:01:00Z"
  });

  assert.equal(validateResourceNotification(notif).ok, true);
  assert.match(notif.content_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal("data" in notif, false);

  const leaky = { ...notif, data: { active_tab: "hotels" } };
  const leakyRes = validateResourceNotification(leaky);
  assert.equal(leakyRes.ok, false);
  assert.equal(leakyRes.error.error_code, "TP-RES004");
});

test("deterministic LWW convergence across all delivery permutations ordered by (sync_version, updated_at, actor_fay_id)", () => {
  assert.equal(
    compareLwwTuple(
      { sync_version: 2, updated_at: "2026-11-16T00:00:00Z", actor_fay_id: ALICE_FAY_ID },
      { sync_version: 1, updated_at: "2026-11-16T01:00:00Z", actor_fay_id: CAROL_FAY_ID }
    ) > 0,
    true
  );

  // Same sync_version & timestamp -> actor_fay_id lexicographic tie-breaker
  assert.equal(
    compareLwwTuple(
      { sync_version: 5, updated_at: "2026-11-16T00:05:00Z", actor_fay_id: ALICE_FAY_ID },
      { sync_version: 5, updated_at: "2026-11-16T00:05:00Z", actor_fay_id: BOB_FAY_ID }
    ) > 0, // "ifay_..." > "cofay_..."
    true
  );

  const updates = [
    {
      resource_id: "itinerary_draft",
      value: { city: "Osaka" },
      sync_version: 3,
      updated_at: "2026-11-16T00:03:00Z",
      actor_fay_id: BOB_FAY_ID
    },
    {
      resource_id: "itinerary_draft",
      value: { city: "Kyoto" },
      sync_version: 3,
      updated_at: "2026-11-16T00:03:00Z",
      actor_fay_id: ALICE_FAY_ID
    },
    {
      resource_id: "itinerary_draft",
      value: { city: "Nara" },
      sync_version: 2,
      updated_at: "2026-11-16T00:09:00Z",
      actor_fay_id: CAROL_FAY_ID
    },
    {
      resource_id: "budget_cap",
      value: { max_cny: 4800 },
      sync_version: 4,
      updated_at: "2026-11-16T00:04:00Z",
      actor_fay_id: BOB_FAY_ID
    }
  ];

  // Property-style check over all 24 permutations of 4 concurrent updates
  const permutations = [];
  function permute(arr, m = []) {
    if (arr.length === 0) {
      permutations.push(m);
    } else {
      for (let i = 0; i < arr.length; i++) {
        const curr = arr.slice();
        const next = curr.splice(i, 1);
        permute(curr, m.concat(next));
      }
    }
  }
  permute(updates);
  assert.equal(permutations.length, 24);

  let baselineSnapshot = null;
  for (const ordering of permutations) {
    let state = {};
    for (const u of ordering) {
      state = mergeCollaborativeResourcesLww(state, { [u.resource_id]: u });
    }
    const serialized = JSON.stringify(state);
    if (baselineSnapshot === null) {
      baselineSnapshot = serialized;
    } else {
      assert.equal(serialized, baselineSnapshot);
    }
  }

  const converged = JSON.parse(baselineSnapshot);
  assert.deepEqual(converged.itinerary_draft.value, { city: "Kyoto" });
  assert.equal(converged.itinerary_draft.actor_fay_id, ALICE_FAY_ID);
  assert.deepEqual(converged.budget_cap.value, { max_cny: 4800 });
});

test("SharedContextManager enforces 5-state lifecycle, delegated_access read-only rule, expiration (TP-CTX002), and revocation (TP-CTX003)", () => {
  const alice = makeAliceIdentity();
  const bob = makeBobIdentity();
  const mgr = new SharedContextManager();

  const created = mgr.createContext({
    contextId: "ctx_lifecycle_01",
    participants: [alice, bob],
    mode: "delegated_access",
    expiration: "2026-11-16T01:00:00Z",
    nowIso: "2026-11-16T00:00:00Z"
  });
  assert.equal(created.ok, true);
  assert.equal(created.context.lifecycle.state, "initializing");

  assert.equal(mgr.activateContext("ctx_lifecycle_01", "2026-11-16T00:00:05Z").ok, true);
  assert.equal(mgr.getContext("ctx_lifecycle_01").lifecycle.state, "active");

  assert.equal(mgr.beginSync("ctx_lifecycle_01", "2026-11-16T00:01:00Z").ok, true);
  assert.equal(mgr.getContext("ctx_lifecycle_01").lifecycle.state, "syncing");
  assert.equal(mgr.completeSync("ctx_lifecycle_01", ALICE_FAY_ID, "2026-11-16T00:01:02Z").ok, true);
  assert.equal(mgr.getContext("ctx_lifecycle_01").lifecycle.state, "active");

  assert.equal(mgr.suspendContext("ctx_lifecycle_01", "2026-11-16T00:02:00Z").ok, true);
  assert.equal(mgr.getContext("ctx_lifecycle_01").lifecycle.state, "suspended");
  assert.equal(mgr.activateContext("ctx_lifecycle_01", "2026-11-16T00:02:30Z").ok, true);

  // Mount resource owned by Alice; Bob cannot write in delegated_access mode (TP-RES001)
  const mountRes = mgr.mountResource("ctx_lifecycle_01", {
    resource: {
      resource_id: "res_delegated_1",
      resource_type: "memory_fragment",
      content_ref: { mode: "inline", data: { seat: "window" }, size_bytes: 17 },
      access_policy: { owner_fay_id: ALICE_FAY_ID, visibility: "shared", requires_encryption: false },
      schema_ref: "https://ifay.ai/schemas/pref.json",
      metadata: { created_at: "2026-11-16T00:00:00Z", updated_at: "2026-11-16T00:00:00Z", version: 1 }
    },
    mount_point: "/prefs/seat",
    owner_fay_id: ALICE_FAY_ID,
    permissions: {
      [ALICE_FAY_ID]: { read: true, write: true },
      [BOB_FAY_ID]: { read: true, write: false }
    }
  });
  assert.equal(mountRes.ok, true);

  const bobWrite = mgr.checkAccess("ctx_lifecycle_01", BOB_FAY_ID, "/prefs/seat", "write", "2026-11-16T00:10:00Z");
  assert.equal(bobWrite.ok, false);
  assert.equal(bobWrite.error.error_code, "TP-RES001");

  // Time expiration check triggers terminated + TP-CTX002
  const expiredAccess = mgr.checkAccess("ctx_lifecycle_01", BOB_FAY_ID, "/prefs/seat", "read", "2026-11-16T02:00:00Z");
  assert.equal(expiredAccess.ok, false);
  assert.equal(expiredAccess.error.error_code, "TP-CTX002");
  assert.equal(mgr.getContext("ctx_lifecycle_01").lifecycle.state, "terminated");
  assert.equal(mgr.getContext("ctx_lifecycle_01").lifecycle.termination_reason, "expired");

  // Immediate unilateral revocation triggers terminated + TP-CTX003
  mgr.createContext({
    contextId: "ctx_revoke_02",
    participants: [alice, bob],
    mode: "collaborative_space",
    nowIso: "2026-11-16T00:00:00Z"
  });
  mgr.activateContext("ctx_revoke_02", "2026-11-16T00:00:01Z");
  mgr.revokeContext("ctx_revoke_02", ALICE_FAY_ID, "Human Prime withdrew sharing authorization", "2026-11-16T00:05:00Z");
  const afterRevoke = mgr.checkAccess("ctx_revoke_02", BOB_FAY_ID, "/any", "read", "2026-11-16T00:05:01Z");
  assert.equal(afterRevoke.ok, false);
  assert.equal(afterRevoke.error.error_code, "TP-CTX003");
});

test("encryptPayload and decryptPayload perform X25519 + AES-256-GCM with SelectiveDisclosure redaction", () => {
  const aliceX = deriveX25519KeyPairFromSeed(SEED_X25519_ALICE_HEX);
  const bobX = deriveX25519KeyPairFromSeed(SEED_X25519_BOB_HEX);

  const fullPrivateData = {
    dietary_preference: "vegetarian",
    preferred_departure_window: "09:00-11:00",
    passport_number: "REDACTED_SENSITIVE_DOC_9988",
    home_street_address: "Hidden Lane 42"
  };

  const encRes = encryptPayload(fullPrivateData, aliceX.privateKey, bobX.publicKeyB64, {
    auditRef: "aud_enc_001",
    disclosedFields: ["dietary_preference", "preferred_departure_window"],
    policyRef: "fp_policy_minimal_disclosure"
  });
  assert.equal(encRes.ok, true);
  assert.equal(encRes.encryptedPayload.encryption_algorithm, "AES-256-GCM");
  assert.deepEqual(encRes.encryptedPayload.selective_disclosure.disclosed_fields, [
    "dietary_preference",
    "preferred_departure_window"
  ]);
  assert.match(
    encRes.encryptedPayload.selective_disclosure.redacted_field_digests.passport_number,
    /^sha256:[0-9a-f]{64}$/
  );

  const decRes = decryptPayload(encRes.encryptedPayload, bobX.privateKey);
  assert.equal(decRes.ok, true);
  assert.deepEqual(decRes.data, {
    dietary_preference: "vegetarian",
    preferred_departure_window: "09:00-11:00"
  });
  assert.equal("passport_number" in decRes.data, false);

  // Tamper ciphertext -> TP-SEC003
  const bad = structuredClone(encRes.encryptedPayload);
  bad.encrypted_data = Buffer.from("corrupted-ciphertext-bytes").toString("base64");
  const badRes = decryptPayload(bad, bobX.privateKey);
  assert.equal(badRes.ok, false);
  assert.equal(badRes.error.error_code, "TP-SEC003");
});

test("CallbackCredentialRegistry enforces expiry (TP-C001), in-band credential_revoke (TP-C002), and scope (TP-C003)", () => {
  const reg = new CallbackCredentialRegistry();
  const issued = reg.issueCredential({
    credential_id: "cred_001",
    scope: {
      resources: ["res_calendar_freebusy"],
      operations: ["read"]
    },
    expiration: "2026-11-16T01:00:00Z",
    resource_reference: "tp://ctx_01/res_calendar_freebusy",
    issuer_fay_id: ALICE_FAY_ID,
    holder_fay_id: BOB_FAY_ID,
    encrypted_token: "opaque_encrypted_capability_blob_001",
    revocation_endpoint: "https://revoke.ifay.example.org/v1/credentials"
  });
  assert.equal(issued.ok, true);

  // Valid access within scope & before expiration
  assert.equal(
    reg.verifyAccess("cred_001", "res_calendar_freebusy", "read", "2026-11-16T00:30:00Z").ok,
    true
  );

  // Out-of-scope operation ("write") -> TP-C003
  const scopeErr = reg.verifyAccess("cred_001", "res_calendar_freebusy", "write", "2026-11-16T00:30:00Z");
  assert.equal(scopeErr.ok, false);
  assert.equal(scopeErr.error.error_code, "TP-C003");

  // Expired -> TP-C001
  const expErr = reg.verifyAccess("cred_001", "res_calendar_freebusy", "read", "2026-11-16T01:00:01Z");
  assert.equal(expErr.ok, false);
  assert.equal(expErr.error.error_code, "TP-C001");

  // Mandatory in-band credential_revoke message -> TP-C002 even before expiration!
  const revokeMsgRes = reg.processCredentialRevokeMessage({
    credential_id: "cred_001",
    issuer_fay_id: ALICE_FAY_ID,
    revoked_at: "2026-11-16T00:35:00Z",
    reason: "Consultation completed early"
  });
  assert.equal(revokeMsgRes.ok, true);

  const revokedErr = reg.verifyAccess("cred_001", "res_calendar_freebusy", "read", "2026-11-16T00:40:00Z");
  assert.equal(revokedErr.ok, false);
  assert.equal(revokedErr.error.error_code, "TP-C002");
});

test("AuditChain enforces zero-payload-leak hash chaining and Human Prime local retention compaction (OQ-11)", () => {
  const chain = new AuditChain();
  const r0 = chain.append({
    record_id: "aud_000",
    timestamp: "2026-11-16T00:00:00Z",
    event_type: "context_created",
    actor_fay_id: ALICE_FAY_ID,
    human_prime_id: "prime_alice_001",
    context_id: "ctx_01",
    payloadForDigestOnly: { summary: "Sensitive travel notes never persisted in audit record" }
  });
  assert.equal(r0.ok, true);
  assert.equal("payload" in r0.record, false);
  assert.equal("payloadForDigestOnly" in r0.record, false);
  assert.equal(JSON.stringify(r0.record).includes("Sensitive travel notes"), false);

  const r1 = chain.append({
    record_id: "aud_001",
    timestamp: "2026-11-16T00:10:00Z",
    event_type: "credential_revoked",
    actor_fay_id: ALICE_FAY_ID,
    human_prime_id: "prime_alice_001",
    credential_id: "cred_001",
    payloadForDigestOnly: { credential_id: "cred_001" }
  });
  assert.equal(r1.ok, true);
  assert.equal(r1.record.prev_record_hash, r0.record.record_hash);
  assert.equal(chain.verifyIntegrity().ok, true);

  // Attempting to inject raw payload field directly must fail with TP-AUD001
  const leakAttempt = chain.append({
    record_id: "aud_bad",
    timestamp: "2026-11-16T00:11:00Z",
    event_type: "resource_accessed",
    actor_fay_id: ALICE_FAY_ID,
    encrypted_token: "should_never_be_stored"
  });
  assert.equal(leakAttempt.ok, false);
  assert.equal(leakAttempt.error.error_code, "TP-AUD001");

  // Human Prime local retention compaction removes older records while keeping verifiable anchor
  const compacted = chain.applyHumanPrimeRetentionPolicy({
    humanPrimeId: "prime_alice_001",
    actorFayId: ALICE_FAY_ID,
    beforeTimestamp: "2026-11-16T00:05:00Z",
    nowTimestamp: "2026-11-16T00:20:00Z",
    retentionPolicyRef: "prime_local_30d_purge"
  });
  assert.equal(compacted.ok, true);
  assert.equal(compacted.purgedCount, 1);
  assert.equal(chain.verifyIntegrity().ok, true);
});

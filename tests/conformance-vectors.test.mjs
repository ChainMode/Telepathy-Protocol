import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  deriveEd25519KeyPairFromSeed,
  parseTpVersion,
  validateFayIdentity,
  signEnvelope,
  verifyEnvelope
} from "../src/envelope.mjs";
import {
  negotiateProtocolContract,
  validateCognitiveFrameExchange,
  SessionStateMachine
} from "../src/session.mjs";
import {
  validateCognitiveResource,
  mergeCollaborativeResourcesLww,
  CallbackCredentialRegistry,
  AuditChain
} from "../src/shared-context.mjs";
import {
  validateSubGoalDag,
  ConsultationManager
} from "../src/goals.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.resolve(__dirname, "../vectors/tp-1.0-conformance.json");
const schemaPath = path.resolve(__dirname, "../schemas/tp-1.0.json");

const suite = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
const normativeSchema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

test("TP 1.0 conformance suite metadata and schema alignment", () => {
  assert.equal(suite.protocol, "TP/1.0");
  assert.equal(suite.tp_version, "1.0");
  assert.ok(Array.isArray(suite.vectors));
  assert.ok(suite.vectors.length >= 16, `Expected >= 16 vectors, got ${suite.vectors.length}`);
  assert.equal(normativeSchema.$id, "https://ifay.ai/schemas/tp-1.0.json");
});

function executeConformanceVector(vec) {
  switch (vec.category) {
    case "envelope_signature": {
      const kp = deriveEd25519KeyPairFromSeed(vec.input.seed_hex);
      if (vec.input.sign_dynamically) {
        const signed = signEnvelope(vec.input.envelope, kp.privateKey);
        assert.equal(signed.ok, true);
        return verifyEnvelope(signed.envelope, kp.publicKeyB64);
      }
      return verifyEnvelope(vec.input.envelope, vec.input.public_key_b64 || kp.publicKeyB64);
    }
    case "version_validation":
      return parseTpVersion(vec.input.tp_version);
    case "identity_validation":
      return validateFayIdentity(vec.input.identity);
    case "session_establishment": {
      const sm = new SessionStateMachine({ timeoutMs: 30000, startTimeMs: 0 });
      for (const action of vec.input.steps) {
        let res;
        if (action.op === "negotiate") {
          res = sm.completeNegotiation(action.initiator_offer, action.responder_offer, action.t);
        } else if (action.op === "verify_identities") {
          res = sm.verifyIdentities(action.initiator, action.responder, action.t);
        } else if (action.op === "exchange_profiles") {
          res = sm.exchangeProfiles(action.initiator_profile, action.responder_profile, action.t);
        } else if (action.op === "establish_context") {
          res = sm.establishInitialContext(action.context, action.t);
        } else if (action.op === "ready") {
          res = sm.markReady(action.t);
        }
        if (!res.ok) return res;
      }
      return { ok: sm.state === "ready", state: sm.state };
    }
    case "cognitive_exchange": {
      const neg = negotiateProtocolContract(
        vec.input.initiator_offer,
        vec.input.responder_offer,
        vec.input.negotiation_options || {}
      );
      if (!neg.ok) return neg;
      if (vec.expected.communication_tier) {
        assert.equal(neg.contract.communication_tier, vec.expected.communication_tier);
      }
      if (typeof vec.expected.fallback_active === "boolean") {
        assert.equal(neg.contract.fallback_active, vec.expected.fallback_active);
      }
      return validateCognitiveFrameExchange(vec.input.frame, neg.contract);
    }
    case "lww_convergence": {
      let stateA = {};
      for (const u of vec.input.replica_a_order) {
        stateA = mergeCollaborativeResourcesLww(stateA, { [u.resource_id]: u });
      }
      let stateB = {};
      for (const u of vec.input.replica_b_order) {
        stateB = mergeCollaborativeResourcesLww(stateB, { [u.resource_id]: u });
      }
      assert.deepEqual(stateA, stateB);
      assert.equal(
        stateA[vec.expected.resource_id].actor_fay_id,
        vec.expected.winning_actor_fay_id
      );
      assert.deepEqual(stateA[vec.expected.resource_id].value, vec.expected.winning_value);
      return { ok: true };
    }
    case "credential_access": {
      const reg = new CallbackCredentialRegistry();
      const issued = reg.issueCredential(vec.input.credential);
      if (!issued.ok) return issued;
      if (vec.input.revoke_message) {
        const rev = reg.processCredentialRevokeMessage(vec.input.revoke_message);
        if (!rev.ok) return rev;
      }
      return reg.verifyAccess(
        vec.input.credential.credential_id,
        vec.input.access_request.resource,
        vec.input.access_request.operation,
        vec.input.access_request.at
      );
    }
    case "resource_validation":
      return validateCognitiveResource(vec.input.resource);
    case "goal_dag_and_consult": {
      const dagRes = validateSubGoalDag(vec.input.sub_goals);
      if (!dagRes.ok) return dagRes;
      if (vec.input.consultations) {
        const cm = new ConsultationManager();
        for (const c of vec.input.consultations) {
          const cRes = cm.registerConsultation(c);
          if (!cRes.ok) return cRes;
        }
      }
      return { ok: true };
    }
    case "audit_zero_payload_leak": {
      const chain = new AuditChain();
      for (const entry of vec.input.entries) {
        const res = chain.append(entry);
        if (!res.ok) return res;
        if (vec.input.forbidden_substring) {
          assert.equal(
            JSON.stringify(res.record).includes(vec.input.forbidden_substring),
            false
          );
        }
      }
      return chain.verifyIntegrity();
    }
    default:
      throw new Error(`Unknown conformance vector category: ${vec.category}`);
  }
}

for (const vec of suite.vectors) {
  test(`Conformance Vector ${vec.id}: ${vec.title}`, () => {
    const result = executeConformanceVector(vec);
    assert.equal(result.ok, vec.expected.ok);
    if (!vec.expected.ok && vec.expected.error_code) {
      assert.equal(result.error.error_code, vec.expected.error_code);
    }
  });
}

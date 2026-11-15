import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalizeJcs,
  parseTpVersion,
  validateFayId,
  validateFayIdentity,
  deriveEd25519KeyPairFromSeed,
  validateEnvelope,
  signEnvelope,
  verifyEnvelope
} from "../src/envelope.mjs";
import {
  SEED_ALICE_HEX,
  SEED_BOB_HEX,
  makeAliceIdentity,
  makeBobIdentity
} from "./_fixtures.mjs";

test("parseTpVersion accepts two-segment 1.0 and TP/1.0 and rejects 3-segment SemVer or major!=1", () => {
  const v1 = parseTpVersion("1.0");
  assert.equal(v1.ok, true);
  assert.equal(v1.normalized, "1.0");
  assert.equal(v1.qualified, "TP/1.0");

  const v2 = parseTpVersion("TP/1.0");
  assert.equal(v2.ok, true);
  assert.equal(v2.major, 1);
  assert.equal(v2.minor, 0);

  const vMinor = parseTpVersion("TP/1.2");
  assert.equal(vMinor.ok, true);
  assert.equal(vMinor.minor, 2);

  const semver = parseTpVersion("1.0.0");
  assert.equal(semver.ok, false);
  assert.equal(semver.error.error_code, "TP-VER003");

  const qualifiedSemver = parseTpVersion("TP/1.0.0");
  assert.equal(qualifiedSemver.ok, false);
  assert.equal(qualifiedSemver.error.error_code, "TP-VER003");

  const majorMismatch = parseTpVersion("2.0");
  assert.equal(majorMismatch.ok, false);
  assert.equal(majorMismatch.error.error_code, "TP-VER001");
});

test("canonicalizeJcs produces deterministic RFC 8785 UTF-16 lexicographic key ordering", () => {
  const a = { z: 1, a: [true, -0, "hello"], m: { b: 2, a: 1, ignored: undefined } };
  const b = { m: { a: 1, b: 2 }, a: [true, 0, "hello"], z: 1 };
  assert.equal(canonicalizeJcs(a), canonicalizeJcs(b));
  assert.equal(canonicalizeJcs(a), '{"a":[true,0,"hello"],"m":{"a":1,"b":2},"z":1}');
});

test("validateFayId and validateFayIdentity enforce ifay_/cofay_ prefixes and Human Prime attribution", () => {
  assert.equal(validateFayId("ifay_alice234567abcdef").ok, true);
  assert.equal(validateFayId("cofay_bobservice234567ab").ok, true);
  assert.equal(validateFayId("fay:alice:001").ok, false);
  assert.equal(validateFayId("IFAY_UPPERCASE2345678").ok, false);

  const validAlice = makeAliceIdentity();
  assert.equal(validateFayIdentity(validAlice).ok, true);

  const missingHumanPrime = { ...validAlice };
  delete missingHumanPrime.human_prime_id;
  const missingRes = validateFayIdentity(missingHumanPrime);
  assert.equal(missingRes.ok, false);
  assert.equal(missingRes.error.error_code, "TP-ID002");

  // Legacy forbidden human host_id must be rejected deterministically
  const forbiddenLegacy = { ...makeBobIdentity(), ["host" + "_id"]: "legacy_bad" };
  const legacyRes = validateFayIdentity(forbiddenLegacy);
  assert.equal(legacyRes.ok, false);
  assert.equal(legacyRes.error.error_code, "TP-ID002");
});

test("signEnvelope and verifyEnvelope round-trip with Ed25519 over JCS and detect tampering", () => {
  const aliceKeys = deriveEd25519KeyPairFromSeed(SEED_ALICE_HEX);
  const bobKeys = deriveEd25519KeyPairFromSeed(SEED_BOB_HEX);
  const envelope = {
    tp_version: "1.0",
    message_id: "01933b4a-7c10-7000-8000-000000000001",
    sender: makeAliceIdentity(aliceKeys.publicKeyB64),
    receiver: makeBobIdentity(bobKeys.publicKeyB64),
    timestamp: "2026-11-16T00:10:00Z",
    message_type: "negotiate_request",
    payload: {
      supported_versions: ["1.0"],
      proposed_transports: [{ protocol: "native_tp", version: "1.0" }]
    }
  };

  const signed = signEnvelope(envelope, aliceKeys.privateKey);
  assert.equal(signed.ok, true);
  assert.equal(signed.envelope.crypto_suite, "Ed25519");
  assert.equal(typeof signed.envelope.signature, "string");

  const verified = verifyEnvelope(signed.envelope, aliceKeys.publicKeyB64);
  assert.equal(verified.ok, true);

  // Wrong public key fails with TP-SEC001
  const wrongKey = verifyEnvelope(signed.envelope, bobKeys.publicKeyB64);
  assert.equal(wrongKey.ok, false);
  assert.equal(wrongKey.error.error_code, "TP-SEC001");

  // Mutating payload invalidates JCS Ed25519 signature
  const tampered = structuredClone(signed.envelope);
  tampered.payload.supported_versions = ["1.1"];
  const tamperedRes = verifyEnvelope(tampered, aliceKeys.publicKeyB64);
  assert.equal(tamperedRes.ok, false);
  assert.equal(tamperedRes.error.error_code, "TP-SEC001");
});

test("ML-DSA-65 post-quantum agility slot is recognized in schema validation and returns TP-SEC002 until PQ signer injected", () => {
  const aliceKeys = deriveEd25519KeyPairFromSeed(SEED_ALICE_HEX);
  const envelope = {
    tp_version: "1.0",
    message_id: "01933b4a-7c10-7000-8000-000000000002",
    sender: makeAliceIdentity(aliceKeys.publicKeyB64),
    receiver: makeBobIdentity(),
    timestamp: "2026-11-16T00:10:01Z",
    message_type: "negotiate_request",
    crypto_suite: "ML-DSA-65",
    payload: { hello: true }
  };

  assert.equal(validateEnvelope(envelope).ok, true);
  const pqSignAttempt = signEnvelope(envelope, aliceKeys.privateKey, { cryptoSuite: "ML-DSA-65" });
  assert.equal(pqSignAttempt.ok, false);
  assert.equal(pqSignAttempt.error.error_code, "TP-SEC002");
});

test("validateEnvelope rejects hop_count > 5 with TP-TRA001 and unknown fields with TP-ENV001", () => {
  const base = {
    tp_version: "1.0",
    message_id: "01933b4a-7c10-7000-8000-000000000003",
    sender: makeAliceIdentity(),
    receiver: makeBobIdentity(),
    timestamp: "2026-11-16T00:10:02Z",
    message_type: "goal_propose",
    payload: { goal_id: "g1" },
    trace_info: {
      original_protocol: "a2a",
      original_message_id: "rpc-1",
      hop_count: 6
    }
  };
  const hopRes = validateEnvelope(base);
  assert.equal(hopRes.ok, false);
  assert.equal(hopRes.error.error_code, "TP-TRA001");

  const extraField = { ...base, trace_info: { original_protocol: "a2a", original_message_id: "rpc-1", hop_count: 2 }, unexpected: 123 };
  const envRes = validateEnvelope(extraField);
  assert.equal(envRes.ok, false);
  assert.equal(envRes.error.error_code, "TP-ENV001");
});

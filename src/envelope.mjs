import crypto from "node:crypto";

export const TP_WIRE_VERSION = "1.0";
export const TP_QUALIFIED_VERSION = "TP/1.0";

export const SUPPORTED_CRYPTO_SUITES = Object.freeze(["Ed25519", "ML-DSA-65"]);

export const MESSAGE_TYPES = Object.freeze([
  "identity_proof",
  "profile_exchange",
  "context_create",
  "context_update",
  "context_sync",
  "context_revoke",
  "resource_mount",
  "resource_unmount",
  "resource_notify",
  "cognitive_frame",
  "credential_revoke",
  "goal_propose",
  "goal_negotiate",
  "goal_accept",
  "goal_reject",
  "goal_result",
  "consultation_request",
  "consultation_response",
  "negotiate_request",
  "negotiate_response",
  "session_ready",
  "error"
]);

const MESSAGE_TYPE_SET = new Set(MESSAGE_TYPES);
const FAY_ID_REGEX = /^(ifay|cofay)_[a-z2-7]{16,64}$/;
const TP_VERSION_REGEX = /^(?:TP\/)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// RFC 8410 / PKCS#8 v1 prefix for a 32-byte Ed25519 private seed (OID 1.3.101.112)
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// SubjectPublicKeyInfo prefix for a 32-byte Ed25519 public key (OID 1.3.101.112)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const ALLOWED_IDENTITY_KEYS = new Set([
  "fay_id",
  "fay_type",
  "human_prime_id",
  "fp_authorization_ref",
  "did"
]);

const ALLOWED_ENVELOPE_KEYS = new Set([
  "tp_version",
  "message_id",
  "sender",
  "receiver",
  "timestamp",
  "message_type",
  "payload",
  "correlation_id",
  "crypto_suite",
  "signature",
  "protocol_contract_ref",
  "icp_annotations",
  "trace_info"
]);

export function createTpError(errorCode, message, details = undefined, correlationId = undefined, recoverySuggestions = undefined) {
  const err = {
    error_code: errorCode,
    message
  };
  if (details !== undefined) err.details = details;
  if (recoverySuggestions !== undefined) err.recovery_suggestions = recoverySuggestions;
  if (correlationId !== undefined) err.correlation_id = correlationId;
  return err;
}

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 * Deterministic serialization with UTF-16 code-unit lexicographic object key ordering
 * and ECMAScript Number-to-String serialization (-0 normalized to 0).
 */
export function canonicalizeJcs(value) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("RFC 8785 JCS forbids NaN and Infinity numbers");
    }
    if (Object.is(value, -0)) {
      return "0";
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalizeJcs(item === undefined ? null : item));
    return `[${items.join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort(); // JS Array.prototype.sort() sorts strings by UTF-16 code units per RFC 8785 §3.2.3
    const props = keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJcs(value[k])}`);
    return `{${props.join(",")}}`;
  }
  throw new TypeError(`Unsupported value type for JCS canonicalization: ${typeof value}`);
}

export function sha256Digest(input) {
  let bytes;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    bytes = input;
  } else if (typeof input === "string") {
    bytes = Buffer.from(input, "utf8");
  } else {
    bytes = Buffer.from(canonicalizeJcs(input), "utf8");
  }
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

export function parseTpVersion(versionString) {
  if (typeof versionString !== "string" || versionString.length === 0) {
    return {
      ok: false,
      error: createTpError("TP-VER003", "Missing or non-string tp_version; expected two-segment MAJOR.MINOR (e.g. \"1.0\" or \"TP/1.0\").")
    };
  }
  const match = TP_VERSION_REGEX.exec(versionString);
  if (!match) {
    return {
      ok: false,
      error: createTpError(
        "TP-VER003",
        `Malformed wire version "${versionString}": TP uses two-segment MAJOR.MINOR ("1.0" or "TP/1.0"); three-segment SemVer is forbidden.`,
        { received: versionString }
      )
    };
  }
  const major = Number.parseInt(match[1], 10);
  const minor = Number.parseInt(match[2], 10);
  if (major !== 1) {
    return {
      ok: false,
      error: createTpError(
        "TP-VER001",
        `Unsupported TP major version ${major}; this SDK implements TP/1.x.`,
        { major, minor }
      )
    };
  }
  return {
    ok: true,
    major,
    minor,
    normalized: `${major}.${minor}`,
    qualified: `TP/${major}.${minor}`
  };
}

export function validateFayId(fayId) {
  if (typeof fayId !== "string") {
    return {
      ok: false,
      error: createTpError("TP-ID001", "fay_id must be a string matching ^(ifay|cofay)_[a-z2-7]{16,64}$.")
    };
  }
  const m = FAY_ID_REGEX.exec(fayId);
  if (!m) {
    return {
      ok: false,
      error: createTpError(
        "TP-ID001",
        `Invalid FayID "${fayId}": must start with ifay_ or cofay_ followed by 16..64 lowercase base32 chars.`,
        { fay_id: fayId }
      )
    };
  }
  return {
    ok: true,
    kind: m[1] === "ifay" ? "iFay" : "coFay"
  };
}

export function validateFayIdentity(identity) {
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
    return {
      ok: false,
      error: createTpError("TP-ID002", "FayIdentity must be a non-null JSON object.")
    };
  }
  for (const key of Object.keys(identity)) {
    if (!ALLOWED_IDENTITY_KEYS.has(key)) {
      return {
        ok: false,
        error: createTpError(
          "TP-ID002",
          `Unexpected or deprecated field "${key}" in FayIdentity; use human_prime_id and fp_authorization_ref.`,
          { invalid_field: key }
        )
      };
    }
  }

  const idRes = validateFayId(identity.fay_id);
  if (!idRes.ok) return idRes;

  if (identity.fay_type !== "iFay" && identity.fay_type !== "coFay") {
    return {
      ok: false,
      error: createTpError("TP-ID002", "fay_type must be \"iFay\" or \"coFay\".")
    };
  }
  if (identity.fay_type !== idRes.kind) {
    return {
      ok: false,
      error: createTpError(
        "TP-ID001",
        `FayID prefix (${idRes.kind}) does not match fay_type (${identity.fay_type}).`
      )
    };
  }
  if (identity.fay_type === "iFay") {
    if (typeof identity.human_prime_id !== "string" || identity.human_prime_id.trim().length === 0) {
      return {
        ok: false,
        error: createTpError("TP-ID002", "human_prime_id MUST be present and non-empty when fay_type is \"iFay\".")
      };
    }
  }

  const did = identity.did;
  if (
    !did ||
    typeof did !== "object" ||
    !["did:key", "did:web", "did:chain"].includes(did.method) ||
    typeof did.value !== "string" ||
    did.value.length < 8 ||
    !did.proof ||
    typeof did.proof.proof_value !== "string" ||
    typeof did.proof.verification_method !== "string" ||
    typeof did.proof.created !== "string"
  ) {
    return {
      ok: false,
      error: createTpError("TP-ID001", "Invalid or incomplete DIDIdentifier / DIDProof in FayIdentity.")
    };
  }

  return { ok: true };
}

export function deriveEd25519KeyPairFromSeed(seedHexOrBytes) {
  const seed = typeof seedHexOrBytes === "string"
    ? Buffer.from(seedHexOrBytes, "hex")
    : Buffer.from(seedHexOrBytes);
  if (seed.length !== 32) {
    throw new RangeError(`Ed25519 seed must be 32 bytes, received ${seed.length}`);
  }
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  const publicKey = crypto.createPublicKey(privateKey);
  const spkiDer = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spkiDer.subarray(ED25519_SPKI_PREFIX.length);
  return {
    privateKey,
    publicKey,
    publicKeyB64: rawPub.toString("base64")
  };
}

function resolveEd25519PublicKey(publicKeyOrB64) {
  if (typeof publicKeyOrB64 === "string") {
    const raw = Buffer.from(publicKeyOrB64, "base64");
    if (raw.length !== 32) {
      throw new RangeError("Base64 Ed25519 public key must decode to 32 raw bytes");
    }
    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    return crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  }
  return publicKeyOrB64;
}

export function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return {
      ok: false,
      error: createTpError("TP-ENV001", "MessageEnvelope must be a JSON object.")
    };
  }

  for (const key of Object.keys(envelope)) {
    if (!ALLOWED_ENVELOPE_KEYS.has(key)) {
      return {
        ok: false,
        error: createTpError("TP-ENV001", `Unknown MessageEnvelope field "${key}".`, { field: key })
      };
    }
  }

  const verRes = parseTpVersion(envelope.tp_version);
  if (!verRes.ok) return verRes;

  if (typeof envelope.message_id !== "string" || !UUID_REGEX.test(envelope.message_id)) {
    return {
      ok: false,
      error: createTpError("TP-ENV001", "message_id must be a valid UUID string.")
    };
  }

  const senderRes = validateFayIdentity(envelope.sender);
  if (!senderRes.ok) return senderRes;

  const receiverRes = validateFayIdentity(envelope.receiver);
  if (!receiverRes.ok) return receiverRes;

  if (typeof envelope.timestamp !== "string" || Number.isNaN(Date.parse(envelope.timestamp))) {
    return {
      ok: false,
      error: createTpError("TP-ENV001", "timestamp must be a valid ISO 8601 date-time string.")
    };
  }

  if (!MESSAGE_TYPE_SET.has(envelope.message_type)) {
    return {
      ok: false,
      error: createTpError("TP-ENV002", `Unsupported message_type "${envelope.message_type}".`)
    };
  }

  if (envelope.payload === undefined) {
    return {
      ok: false,
      error: createTpError("TP-ENV001", "payload field is required on MessageEnvelope.")
    };
  }

  if (
    envelope.crypto_suite !== undefined &&
    !SUPPORTED_CRYPTO_SUITES.includes(envelope.crypto_suite)
  ) {
    return {
      ok: false,
      error: createTpError("TP-SEC002", `Unsupported crypto_suite "${envelope.crypto_suite}".`)
    };
  }

  if (envelope.trace_info !== undefined) {
    const ti = envelope.trace_info;
    if (
      !ti ||
      typeof ti !== "object" ||
      typeof ti.original_protocol !== "string" ||
      typeof ti.original_message_id !== "string" ||
      typeof ti.hop_count !== "number" ||
      !Number.isInteger(ti.hop_count) ||
      ti.hop_count < 0
    ) {
      return {
        ok: false,
        error: createTpError("TP-ENV001", "Malformed trace_info object.")
      };
    }
    if (ti.hop_count > 5) {
      return {
        ok: false,
        error: createTpError("TP-TRA001", `Cross-protocol hop_count (${ti.hop_count}) exceeds maximum of 5.`)
      };
    }
  }

  return { ok: true, version: verRes };
}

export function signEnvelope(envelope, privateKey, options = {}) {
  const cryptoSuite = options.cryptoSuite ?? envelope.crypto_suite ?? "Ed25519";
  const unsigned = structuredClone(envelope);
  delete unsigned.signature;
  unsigned.crypto_suite = cryptoSuite;

  const valid = validateEnvelope(unsigned);
  if (!valid.ok) return valid;

  if (cryptoSuite === "ML-DSA-65") {
    if (typeof options.pqSignFn === "function") {
      const jcsBytes = Buffer.from(canonicalizeJcs(unsigned), "utf8");
      const sigB64 = options.pqSignFn(jcsBytes, privateKey);
      return {
        ok: true,
        envelope: { ...unsigned, signature: sigB64 }
      };
    }
    return {
      ok: false,
      error: createTpError(
        "TP-SEC002",
        "ML-DSA-65 is a reserved post-quantum negotiation slot in TP/1.0; inject options.pqSignFn or negotiate Ed25519 MTI."
      )
    };
  }

  const jcsBytes = Buffer.from(canonicalizeJcs(unsigned), "utf8");
  const sig = crypto.sign(null, jcsBytes, privateKey);
  return {
    ok: true,
    envelope: {
      ...unsigned,
      signature: sig.toString("base64")
    }
  };
}

export function verifyEnvelope(envelope, publicKeyOrB64, options = {}) {
  const valid = validateEnvelope(envelope);
  if (!valid.ok) return valid;

  if (typeof envelope.signature !== "string" || envelope.signature.length === 0) {
    return {
      ok: false,
      error: createTpError("TP-SEC001", "Missing MessageEnvelope signature.")
    };
  }

  const suite = envelope.crypto_suite ?? "Ed25519";
  const unsigned = structuredClone(envelope);
  delete unsigned.signature;
  const jcsBytes = Buffer.from(canonicalizeJcs(unsigned), "utf8");

  if (suite === "ML-DSA-65") {
    if (typeof options.pqVerifyFn === "function") {
      const ok = Boolean(options.pqVerifyFn(jcsBytes, envelope.signature, publicKeyOrB64));
      return ok
        ? { ok: true }
        : { ok: false, error: createTpError("TP-SEC001", "ML-DSA-65 signature verification failed.") };
    }
    return {
      ok: false,
      error: createTpError("TP-SEC002", "ML-DSA-65 verifier not active without options.pqVerifyFn.")
    };
  }

  try {
    const pubKey = resolveEd25519PublicKey(publicKeyOrB64);
    const sigBytes = Buffer.from(envelope.signature, "base64");
    const verified = crypto.verify(null, jcsBytes, pubKey, sigBytes);
    if (!verified) {
      return {
        ok: false,
        error: createTpError("TP-SEC001", "Ed25519 signature verification failed over RFC 8785 JCS envelope.")
      };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error: createTpError("TP-SEC001", `Signature verification error: ${err.message}`)
    };
  }
}

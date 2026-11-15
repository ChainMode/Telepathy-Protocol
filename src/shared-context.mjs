import crypto from "node:crypto";
import net from "node:net";
import {
  createTpError,
  canonicalizeJcs,
  sha256Digest,
  validateFayId,
  validateFayIdentity
} from "./envelope.mjs";

export const MAX_INLINE_BYTES = 65_536; // 64 KiB normative ceiling
export const AUDIT_GENESIS_HASH = `sha256:${"0".repeat(64)}`;

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function isDisallowedIpv4Octets(o) {
  const [a, b] = o;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8 RFC 1918
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local & cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC 1918
  if (a === 192 && b === 0 && o[2] === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC 1918
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15
  if (a >= 224) return true; // multicast & broadcast
  return false;
}

function expandIpv6ToWords(ipv6Str) {
  let normalized = ipv6Str.split("%")[0].toLowerCase();
  const lastColon = normalized.lastIndexOf(":");
  if (normalized.includes(".")) {
    const ipv4Part = normalized.slice(lastColon + 1);
    const octs = ipv4Part.split(".").map((n) => Number.parseInt(n, 10));
    if (octs.length !== 4 || octs.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    const w1 = ((octs[0] << 8) | octs[1]).toString(16);
    const w2 = ((octs[2] << 8) | octs[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${w1}:${w2}`;
  }

  const parts = normalized.split("::");
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const missing = 8 - (head.length + tail.length);
  if ((parts.length === 1 && missing !== 0) || missing < 0) return null;

  const full = [...head, ...Array(missing).fill("0"), ...tail];
  if (full.length !== 8) return null;
  const words = full.map((h) => Number.parseInt(h, 16));
  if (words.some((w) => Number.isNaN(w) || w < 0 || w > 0xffff)) return null;
  return words;
}

function isDisallowedIpv6(ipv6Str) {
  const words = expandIpv6ToWords(ipv6Str);
  if (!words) return true;
  const allZeroExceptLast = words.slice(0, 7).every((w) => w === 0);
  if (allZeroExceptLast && (words[7] === 0 || words[7] === 1)) return true; // :: or ::1
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    (words[5] === 0xffff || words[5] === 0)
  ) {
    const octs = [
      (words[6] >> 8) & 0xff,
      words[6] & 0xff,
      (words[7] >> 8) & 0xff,
      words[7] & 0xff
    ];
    if (isDisallowedIpv4Octets(octs)) return true;
  }
  const first = words[0];
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  if ((first & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (words[0] === 0x2001 && words[1] === 0x0db8) return true;
  return false;
}

export function validateSafeReferenceUri(uriString) {
  if (typeof uriString !== "string" || uriString.length === 0) {
    return { ok: false, error: createTpError("TP-RES002", "Reference URI must be a non-empty https:// URL.") };
  }
  let parsed;
  try {
    parsed = new URL(uriString);
  } catch {
    return { ok: false, error: createTpError("TP-RES002", `Malformed reference URI "${uriString}".`) };
  }
  if (parsed.protocol !== "https:") {
    return {
      ok: false,
      error: createTpError("TP-RES002", `Unsafe URI scheme "${parsed.protocol}": only https:// is permitted.`)
    };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: createTpError("TP-RES002", "Reference URI must not embed userinfo credentials.") };
  }
  const rawHost = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (
    !rawHost ||
    rawHost === "localhost" ||
    rawHost.endsWith(".localhost") ||
    rawHost.endsWith(".local") ||
    rawHost.endsWith(".internal")
  ) {
    return { ok: false, error: createTpError("TP-RES002", `SSRF guard rejected local hostname "${rawHost}".`) };
  }
  if (rawHost.startsWith("[") && rawHost.endsWith("]")) {
    const ipv6 = rawHost.slice(1, -1);
    if (isDisallowedIpv6(ipv6)) {
      return { ok: false, error: createTpError("TP-RES002", `SSRF guard rejected IPv6 "${ipv6}".`) };
    }
    return { ok: true, url: parsed.toString() };
  }
  if (net.isIPv4(rawHost)) {
    const octs = rawHost.split(".").map((s) => Number.parseInt(s, 10));
    if (isDisallowedIpv4Octets(octs)) {
      return { ok: false, error: createTpError("TP-RES002", `SSRF guard rejected IPv4 "${rawHost}".`) };
    }
    return { ok: true, url: parsed.toString() };
  }
  if (/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(rawHost)) {
    return { ok: false, error: createTpError("TP-RES002", `SSRF guard rejected numeric host "${rawHost}".`) };
  }
  return { ok: true, url: parsed.toString() };
}

export function validateCognitiveResource(resource) {
  if (
    !resource ||
    typeof resource !== "object" ||
    typeof resource.resource_id !== "string" ||
    resource.resource_id.length === 0 ||
    !["memory_fragment", "view_state", "reasoning_engine", "environment_context"].includes(
      resource.resource_type
    ) ||
    !resource.content_ref ||
    !resource.access_policy ||
    typeof resource.schema_ref !== "string" ||
    !resource.metadata
  ) {
    return { ok: false, error: createTpError("TP-RES001", "Malformed CognitiveResource structure.") };
  }

  const ownerCheck = validateFayId(resource.access_policy.owner_fay_id);
  if (!ownerCheck.ok) return ownerCheck;

  const ref = resource.content_ref;
  if (ref.mode === "inline") {
    if (typeof ref.size_bytes !== "number" || ref.size_bytes < 0 || ref.size_bytes > MAX_INLINE_BYTES) {
      return {
        ok: false,
        error: createTpError("TP-RES003", `Inline size_bytes (${ref.size_bytes}) exceeds 64 KiB (${MAX_INLINE_BYTES}).`)
      };
    }
    const actualBytes = Buffer.byteLength(
      typeof ref.data === "string" ? ref.data : JSON.stringify(ref.data ?? null),
      "utf8"
    );
    if (actualBytes > MAX_INLINE_BYTES) {
      return {
        ok: false,
        error: createTpError("TP-RES003", `Inline payload (${actualBytes} bytes) exceeds 64 KiB (${MAX_INLINE_BYTES}).`)
      };
    }
    return { ok: true };
  }
  if (ref.mode === "reference") {
    const uriRes = validateSafeReferenceUri(ref.uri);
    if (!uriRes.ok) return uriRes;
    if (typeof ref.content_type !== "string" || typeof ref.size_bytes !== "number" || ref.size_bytes < 0) {
      return { ok: false, error: createTpError("TP-RES002", "ReferenceContent requires content_type and size_bytes.") };
    }
    return { ok: true };
  }
  if (ref.mode === "dtp_tunnel") {
    if (typeof ref.tunnel_id !== "string" || !Number.isInteger(ref.stream_id) || ref.stream_id < 1) {
      return { ok: false, error: createTpError("TP-RES002", "Invalid DtpTunnelContent.") };
    }
    return { ok: true };
  }
  return { ok: false, error: createTpError("TP-RES001", `Unsupported content_ref.mode "${ref.mode}".`) };
}

const ALLOWED_NOTIFICATION_KEYS = new Set([
  "context_id",
  "resource_id",
  "resource_type",
  "change_kind",
  "content_digest",
  "byte_length",
  "sync_version",
  "updated_at",
  "actor_fay_id"
]);

export function createResourceNotification({
  contextId,
  resource,
  changeKind,
  syncVersion,
  actorFayId,
  updatedAt = new Date().toISOString()
}) {
  const ref = resource.content_ref;
  const contentDigest =
    ref.checksum ??
    (ref.mode === "inline" ? sha256Digest(ref.data) : sha256Digest(ref.uri ?? ref.tunnel_id));
  return {
    context_id: contextId,
    resource_id: resource.resource_id,
    resource_type: resource.resource_type,
    change_kind: changeKind,
    content_digest: contentDigest,
    byte_length: ref.size_bytes ?? 0,
    sync_version: syncVersion,
    updated_at: updatedAt,
    actor_fay_id: actorFayId
  };
}

export function validateResourceNotification(notification) {
  if (!notification || typeof notification !== "object") {
    return { ok: false, error: createTpError("TP-RES004", "ResourceNotification must be an object.") };
  }
  for (const key of Object.keys(notification)) {
    if (!ALLOWED_NOTIFICATION_KEYS.has(key)) {
      return {
        ok: false,
        error: createTpError("TP-RES004", `Content leak forbidden in ResourceNotification: "${key}".`)
      };
    }
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(notification.content_digest ?? "")) {
    return { ok: false, error: createTpError("TP-RES004", "ResourceNotification requires sha256 content_digest.") };
  }
  return { ok: true };
}

export function compareLwwTuple(a, b) {
  if (a.sync_version !== b.sync_version) return a.sync_version - b.sync_version;
  const ta = Date.parse(a.updated_at);
  const tb = Date.parse(b.updated_at);
  if (ta !== tb) return ta - tb;
  if (a.updated_at !== b.updated_at) return a.updated_at < b.updated_at ? -1 : 1;
  if (a.actor_fay_id === b.actor_fay_id) return 0;
  return a.actor_fay_id < b.actor_fay_id ? -1 : 1;
}

export function mergeCollaborativeResourcesLww(localStateMap = {}, incomingStateMap = {}) {
  const merged = {};
  const allKeys = new Set([...Object.keys(localStateMap), ...Object.keys(incomingStateMap)].sort());
  for (const key of allKeys) {
    const localEntry = localStateMap[key];
    const incomingEntry = incomingStateMap[key];
    if (!localEntry) {
      merged[key] = structuredClone(incomingEntry);
    } else if (!incomingEntry) {
      merged[key] = structuredClone(localEntry);
    } else {
      merged[key] =
        compareLwwTuple(incomingEntry, localEntry) >= 0
          ? structuredClone(incomingEntry)
          : structuredClone(localEntry);
    }
  }
  return merged;
}

export class SharedContextManager {
  constructor() {
    this.contexts = new Map();
  }

  createContext({
    contextId,
    participants,
    mode = "collaborative_space",
    defaultPolicy = "read_only",
    expiration = undefined,
    expirationEvent = undefined,
    nowIso = new Date().toISOString()
  }) {
    if (!Array.isArray(participants) || participants.length < 2) {
      return { ok: false, error: createTpError("TP-CTX001", "SharedContext requires at least 2 participants.") };
    }
    for (const p of participants) {
      const check = validateFayIdentity(p);
      if (!check.ok) return check;
    }
    const ctx = {
      context_id: contextId,
      participants: structuredClone(participants),
      mode,
      mounted_resources: [],
      access_control: { default_policy: defaultPolicy, per_resource_overrides: [] },
      lifecycle: {
        state: "initializing",
        creation_time: nowIso,
        ...(expiration ? { expiration } : {}),
        ...(expirationEvent ? { expiration_event: expirationEvent } : {}),
        last_state_change: nowIso
      },
      sync_state: {
        sync_version: 0,
        updated_at: nowIso,
        actor_fay_id: participants[0].fay_id,
        conflict_resolution: "last_writer_wins",
        pending_changes: 0
      }
    };
    this.contexts.set(contextId, ctx);
    return { ok: true, context: ctx };
  }

  getContext(contextId) {
    return this.contexts.get(contextId) ?? null;
  }

  #ensureMutable(contextId, nowIso) {
    const ctx = this.contexts.get(contextId);
    if (!ctx) {
      return { ok: false, error: createTpError("TP-CTX001", `Unknown SharedContext "${contextId}".`) };
    }
    if (ctx.lifecycle.state === "terminated") {
      const code =
        ctx.lifecycle.termination_reason === "revoked"
          ? "TP-CTX003"
          : ctx.lifecycle.termination_reason === "expired"
            ? "TP-CTX002"
            : "TP-CTX001";
      return { ok: false, error: createTpError(code, `SharedContext "${contextId}" is terminated.`) };
    }
    if (ctx.lifecycle.expiration && Date.parse(nowIso) >= Date.parse(ctx.lifecycle.expiration)) {
      ctx.lifecycle.state = "terminated";
      ctx.lifecycle.termination_reason = "expired";
      ctx.lifecycle.last_state_change = nowIso;
      ctx.mounted_resources = [];
      return { ok: false, error: createTpError("TP-CTX002", `SharedContext "${contextId}" expired.`) };
    }
    return { ok: true, ctx };
  }

  activateContext(contextId, nowIso = new Date().toISOString()) {
    const check = this.#ensureMutable(contextId, nowIso);
    if (!check.ok) return check;
    const { ctx } = check;
    if (!["initializing", "suspended", "syncing"].includes(ctx.lifecycle.state)) {
      return { ok: false, error: createTpError("TP-CTX001", `Cannot activate from "${ctx.lifecycle.state}".`) };
    }
    ctx.lifecycle.state = "active";
    ctx.lifecycle.last_state_change = nowIso;
    return { ok: true, context: ctx };
  }

  beginSync(contextId, nowIso = new Date().toISOString()) {
    const check = this.#ensureMutable(contextId, nowIso);
    if (!check.ok) return check;
    const { ctx } = check;
    if (ctx.lifecycle.state !== "active") {
      return { ok: false, error: createTpError("TP-CTX004", `Cannot sync from "${ctx.lifecycle.state}".`) };
    }
    ctx.lifecycle.state = "syncing";
    ctx.lifecycle.last_state_change = nowIso;
    return { ok: true, context: ctx };
  }

  completeSync(contextId, actorFayId, nowIso = new Date().toISOString()) {
    const check = this.#ensureMutable(contextId, nowIso);
    if (!check.ok) return check;
    const { ctx } = check;
    if (ctx.lifecycle.state !== "syncing") {
      return { ok: false, error: createTpError("TP-CTX004", "Not in syncing state.") };
    }
    ctx.lifecycle.state = "active";
    ctx.lifecycle.last_state_change = nowIso;
    ctx.sync_state.sync_version += 1;
    ctx.sync_state.updated_at = nowIso;
    ctx.sync_state.actor_fay_id = actorFayId;
    ctx.sync_state.pending_changes = 0;
    return { ok: true, context: ctx };
  }

  suspendContext(contextId, nowIso = new Date().toISOString()) {
    const check = this.#ensureMutable(contextId, nowIso);
    if (!check.ok) return check;
    const { ctx } = check;
    if (ctx.lifecycle.state !== "active") {
      return { ok: false, error: createTpError("TP-CTX001", `Cannot suspend from "${ctx.lifecycle.state}".`) };
    }
    ctx.lifecycle.state = "suspended";
    ctx.lifecycle.last_state_change = nowIso;
    return { ok: true, context: ctx };
  }

  revokeContext(contextId, actorFayId, reason, nowIso = new Date().toISOString()) {
    const ctx = this.contexts.get(contextId);
    if (!ctx) return { ok: false, error: createTpError("TP-CTX001", `Unknown SharedContext "${contextId}".`) };
    if (!ctx.participants.some((p) => p.fay_id === actorFayId)) {
      return { ok: false, error: createTpError("TP-RES001", "Only participants may revoke SharedContext.") };
    }
    ctx.lifecycle.state = "terminated";
    ctx.lifecycle.termination_reason = "revoked";
    ctx.lifecycle.revocation_reason = reason;
    ctx.lifecycle.last_state_change = nowIso;
    ctx.mounted_resources = [];
    return { ok: true, context: ctx };
  }

  mountResource(contextId, mountedResource, nowIso = new Date().toISOString()) {
    const check = this.#ensureMutable(contextId, nowIso);
    if (!check.ok) return check;
    const { ctx } = check;
    if (ctx.lifecycle.state !== "active") {
      return { ok: false, error: createTpError("TP-CTX001", "SharedContext must be active to mount resources.") };
    }
    const resValid = validateCognitiveResource(mountedResource.resource);
    if (!resValid.ok) return resValid;
    const idx = ctx.mounted_resources.findIndex((m) => m.mount_point === mountedResource.mount_point);
    if (idx >= 0) ctx.mounted_resources[idx] = structuredClone(mountedResource);
    else ctx.mounted_resources.push(structuredClone(mountedResource));
    ctx.sync_state.sync_version += 1;
    ctx.sync_state.updated_at = nowIso;
    ctx.sync_state.actor_fay_id = mountedResource.owner_fay_id;
    return { ok: true };
  }

  checkAccess(contextId, actorFayId, mountPoint, operation, nowIso = new Date().toISOString()) {
    const check = this.#ensureMutable(contextId, nowIso);
    if (!check.ok) return check;
    const { ctx } = check;
    if (ctx.lifecycle.state !== "active" && ctx.lifecycle.state !== "syncing") {
      return { ok: false, error: createTpError("TP-CTX001", `Context is "${ctx.lifecycle.state}".`) };
    }
    const mounted = ctx.mounted_resources.find((m) => m.mount_point === mountPoint);
    if (!mounted) {
      return { ok: false, error: createTpError("TP-RES001", `Mount point "${mountPoint}" not found.`) };
    }
    if (ctx.mode === "delegated_access" && operation === "write" && actorFayId !== mounted.owner_fay_id) {
      return { ok: false, error: createTpError("TP-RES001", "delegated_access forbids non-owner writes.") };
    }
    const perm = mounted.permissions?.[actorFayId];
    if (perm) {
      const allowed = operation === "read" ? perm.read === true : perm.write === true;
      return allowed
        ? { ok: true, resource: mounted.resource }
        : { ok: false, error: createTpError("TP-RES001", "ACL denied access.") };
    }
    const def = ctx.access_control.default_policy;
    if (def === "read_write" || (def === "read_only" && operation === "read")) {
      return { ok: true, resource: mounted.resource };
    }
    return { ok: false, error: createTpError("TP-RES001", "Default ACL denied access.") };
  }
}

export function deriveX25519KeyPairFromSeed(seedHexOrBytes) {
  const seed = typeof seedHexOrBytes === "string"
    ? Buffer.from(seedHexOrBytes, "hex")
    : Buffer.from(seedHexOrBytes);
  if (seed.length !== 32) throw new RangeError("X25519 seed must be 32 bytes");
  const pkcs8Der = Buffer.concat([X25519_PKCS8_PREFIX, seed]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  const publicKey = crypto.createPublicKey(privateKey);
  const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(X25519_SPKI_PREFIX.length);
  return { privateKey, publicKey, publicKeyB64: rawPub.toString("base64") };
}

function resolveX25519PublicKey(publicKeyOrB64) {
  if (typeof publicKeyOrB64 === "string") {
    const raw = Buffer.from(publicKeyOrB64, "base64");
    if (raw.length !== 32) throw new RangeError("Base64 X25519 public key must decode to 32 bytes");
    return crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
  }
  return publicKeyOrB64;
}

export function encryptPayload(plaintextObject, senderPrivateKey, receiverPublicKeyOrB64, options = {}) {
  const algorithm = options.encryptionAlgorithm ?? "AES-256-GCM";
  if (algorithm !== "AES-256-GCM") {
    return { ok: false, error: createTpError("TP-SEC005", `Unsupported algorithm "${algorithm}".`) };
  }
  let dataToEncrypt = plaintextObject;
  let selectiveDisclosure;
  if (Array.isArray(options.disclosedFields)) {
    const allowedSet = new Set(options.disclosedFields);
    const filtered = {};
    const redactedDigests = {};
    for (const [k, v] of Object.entries(plaintextObject ?? {})) {
      if (allowedSet.has(k)) filtered[k] = v;
      else redactedDigests[k] = sha256Digest(v);
    }
    dataToEncrypt = filtered;
    selectiveDisclosure = {
      disclosed_fields: [...options.disclosedFields],
      redacted_field_digests: redactedDigests,
      ...(options.policyRef ? { policy_ref: options.policyRef } : {})
    };
  }
  const receiverPubKey = resolveX25519PublicKey(receiverPublicKeyOrB64);
  const senderRawPub = crypto
    .createPublicKey(senderPrivateKey)
    .export({ format: "der", type: "spki" })
    .subarray(X25519_SPKI_PREFIX.length);
  const sharedSecret = crypto.diffieHellman({ privateKey: senderPrivateKey, publicKey: receiverPubKey });
  const salt = options.salt ? Buffer.from(options.salt) : crypto.randomBytes(16);
  const iv = options.iv ? Buffer.from(options.iv) : crypto.randomBytes(12);
  const aesKey = Buffer.from(
    crypto.hkdfSync("sha256", sharedSecret, salt, Buffer.from("TP/1.0-AES-256-GCM", "utf8"), 32)
  );
  const auditRef = options.auditRef ?? "aud_auto";
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  cipher.setAAD(Buffer.from(auditRef, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(canonicalizeJcs(dataToEncrypt), "utf8")), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ok: true,
    encryptedPayload: {
      encryption_algorithm: "AES-256-GCM",
      encrypted_data: ciphertext.toString("base64"),
      key_exchange_info: {
        method: "X25519",
        public_key: senderRawPub.toString("base64"),
        encrypted_session_key: salt.toString("base64"),
        iv: iv.toString("base64"),
        auth_tag: authTag.toString("base64")
      },
      ...(selectiveDisclosure ? { selective_disclosure: selectiveDisclosure } : {}),
      audit_ref: auditRef
    }
  };
}

export function decryptPayload(encryptedPayload, receiverPrivateKey) {
  if (!encryptedPayload || typeof encryptedPayload !== "object") {
    return { ok: false, error: createTpError("TP-SEC003", "EncryptedPayload must be an object.") };
  }
  if (encryptedPayload.encryption_algorithm !== "AES-256-GCM") {
    return { ok: false, error: createTpError("TP-SEC005", "Unsupported encryption_algorithm.") };
  }
  try {
    const kex = encryptedPayload.key_exchange_info;
    const senderPubKey = resolveX25519PublicKey(kex.public_key);
    const sharedSecret = crypto.diffieHellman({ privateKey: receiverPrivateKey, publicKey: senderPubKey });
    const salt = Buffer.from(kex.encrypted_session_key, "base64");
    const iv = Buffer.from(kex.iv, "base64");
    const authTag = Buffer.from(kex.auth_tag, "base64");
    const aesKey = Buffer.from(
      crypto.hkdfSync("sha256", sharedSecret, salt, Buffer.from("TP/1.0-AES-256-GCM", "utf8"), 32)
    );
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAAD(Buffer.from(encryptedPayload.audit_ref, "utf8"));
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedPayload.encrypted_data, "base64")),
      decipher.final()
    ]);
    return { ok: true, data: JSON.parse(decrypted.toString("utf8")) };
  } catch (err) {
    return { ok: false, error: createTpError("TP-SEC003", `Decryption failed: ${err.message}`) };
  }
}

export class CallbackCredentialRegistry {
  constructor({ externalRevocationCheck = null } = {}) {
    this.credentials = new Map();
    this.revoked = new Map();
    this.externalRevocationCheck = externalRevocationCheck;
  }

  issueCredential(credential) {
    if (
      !credential ||
      typeof credential.credential_id !== "string" ||
      !credential.scope ||
      !Array.isArray(credential.scope.resources) ||
      credential.scope.resources.length === 0 ||
      !Array.isArray(credential.scope.operations) ||
      credential.scope.operations.length === 0 ||
      typeof credential.expiration !== "string" ||
      Number.isNaN(Date.parse(credential.expiration)) ||
      typeof credential.encrypted_token !== "string"
    ) {
      return { ok: false, error: createTpError("TP-C003", "Malformed CallbackCredential.") };
    }
    const issuerOk = validateFayId(credential.issuer_fay_id);
    if (!issuerOk.ok) return issuerOk;
    if (credential.revocation_endpoint !== undefined) {
      const epOk = validateSafeReferenceUri(credential.revocation_endpoint);
      if (!epOk.ok) return epOk;
    }
    this.credentials.set(credential.credential_id, structuredClone(credential));
    return { ok: true, credential };
  }

  processCredentialRevokeMessage(revokePayload) {
    if (
      !revokePayload ||
      typeof revokePayload.credential_id !== "string" ||
      typeof revokePayload.issuer_fay_id !== "string" ||
      typeof revokePayload.revoked_at !== "string" ||
      typeof revokePayload.reason !== "string"
    ) {
      return { ok: false, error: createTpError("TP-ENV001", "Malformed CredentialRevocation.") };
    }
    const existing = this.credentials.get(revokePayload.credential_id);
    if (existing && existing.issuer_fay_id !== revokePayload.issuer_fay_id) {
      return { ok: false, error: createTpError("TP-C003", "Issuer mismatch on credential revocation.") };
    }
    this.revoked.set(revokePayload.credential_id, structuredClone(revokePayload));
    return { ok: true };
  }

  verifyAccess(credentialId, resourceId, operation, nowIso = new Date().toISOString()) {
    const cred = this.credentials.get(credentialId);
    if (!cred) {
      return { ok: false, error: createTpError("TP-C003", `Unknown credential "${credentialId}".`) };
    }
    if (
      this.revoked.has(credentialId) ||
      (typeof this.externalRevocationCheck === "function" &&
        cred.revocation_endpoint &&
        this.externalRevocationCheck(credentialId, cred.revocation_endpoint) === true)
    ) {
      return { ok: false, error: createTpError("TP-C002", `Credential "${credentialId}" is revoked.`) };
    }
    if (Date.parse(nowIso) >= Date.parse(cred.expiration)) {
      return { ok: false, error: createTpError("TP-C001", `Credential "${credentialId}" expired.`) };
    }
    if (!cred.scope.resources.includes(resourceId) || !cred.scope.operations.includes(operation)) {
      return { ok: false, error: createTpError("TP-C003", "Credential scope violation.") };
    }
    return { ok: true, credential: cred };
  }
}

const ALLOWED_AUDIT_INPUT_KEYS = new Set([
  "record_id",
  "timestamp",
  "event_type",
  "actor_fay_id",
  "human_prime_id",
  "context_id",
  "resource_id",
  "credential_id",
  "payload_digest",
  "payloadForDigestOnly",
  "retention_policy_ref"
]);

export class AuditChain {
  constructor() {
    this.records = [];
    this.anchorHash = AUDIT_GENESIS_HASH;
    this.nextSequence = 0;
  }

  append(entry) {
    if (!entry || typeof entry !== "object") {
      return { ok: false, error: createTpError("TP-AUD001", "Audit entry must be an object.") };
    }
    for (const key of Object.keys(entry)) {
      if (!ALLOWED_AUDIT_INPUT_KEYS.has(key)) {
        return {
          ok: false,
          error: createTpError("TP-AUD001", `Zero-payload-leak violation: forbidden field "${key}".`)
        };
      }
    }
    const actorOk = validateFayId(entry.actor_fay_id);
    if (!actorOk.ok) return actorOk;
    const payloadDigest = entry.payload_digest ?? sha256Digest(entry.payloadForDigestOnly ?? {});
    if (!/^sha256:[0-9a-f]{64}$/.test(payloadDigest)) {
      return { ok: false, error: createTpError("TP-AUD001", "Invalid payload_digest.") };
    }
    const prevHash =
      this.records.length > 0 ? this.records[this.records.length - 1].record_hash : this.anchorHash;
    const coreRecord = {
      record_id: entry.record_id,
      sequence: this.nextSequence,
      timestamp: entry.timestamp ?? new Date().toISOString(),
      event_type: entry.event_type,
      actor_fay_id: entry.actor_fay_id,
      ...(entry.human_prime_id ? { human_prime_id: entry.human_prime_id } : {}),
      ...(entry.context_id ? { context_id: entry.context_id } : {}),
      ...(entry.resource_id ? { resource_id: entry.resource_id } : {}),
      ...(entry.credential_id ? { credential_id: entry.credential_id } : {}),
      payload_digest: payloadDigest,
      prev_record_hash: prevHash,
      ...(entry.retention_policy_ref ? { retention_policy_ref: entry.retention_policy_ref } : {})
    };
    const fullRecord = { ...coreRecord, record_hash: sha256Digest(coreRecord) };
    this.records.push(fullRecord);
    this.nextSequence += 1;
    return { ok: true, record: fullRecord };
  }

  verifyIntegrity() {
    let expectedPrev = this.anchorHash;
    for (const rec of this.records) {
      if (rec.prev_record_hash !== expectedPrev) {
        return { ok: false, error: createTpError("TP-AUD002", "Broken prev_record_hash link.") };
      }
      const { record_hash: actualHash, ...rest } = rec;
      if (actualHash !== sha256Digest(rest)) {
        return { ok: false, error: createTpError("TP-AUD002", "Tampered AuditRecord hash.") };
      }
      expectedPrev = actualHash;
    }
    return { ok: true, recordCount: this.records.length };
  }

  applyHumanPrimeRetentionPolicy({
    humanPrimeId,
    actorFayId,
    beforeTimestamp,
    nowTimestamp = new Date().toISOString(),
    retentionPolicyRef = "human_prime_local_retention"
  }) {
    const cutoffMs = Date.parse(beforeTimestamp);
    const kept = [];
    const purgedHashes = [];
    for (const rec of this.records) {
      if (rec.human_prime_id === humanPrimeId && Date.parse(rec.timestamp) < cutoffMs) {
        purgedHashes.push(rec.record_hash);
      } else {
        kept.push(rec);
      }
    }
    this.anchorHash = sha256Digest({
      previous_anchor: this.anchorHash,
      purged_record_hashes: purgedHashes,
      human_prime_id: humanPrimeId,
      retention_policy_ref: retentionPolicyRef
    });
    this.records = [];
    this.nextSequence = 0;
    for (const item of kept) {
      const { record_hash: _h, prev_record_hash: _p, sequence: _s, ...rest } = item;
      this.append(rest);
    }
    this.append({
      record_id: `aud_compact_${purgedHashes.length}`,
      timestamp: nowTimestamp,
      event_type: "retention_compacted",
      actor_fay_id: actorFayId,
      human_prime_id: humanPrimeId,
      retention_policy_ref: retentionPolicyRef,
      payloadForDigestOnly: { purged_count: purgedHashes.length }
    });
    return { ok: true, purgedCount: purgedHashes.length };
  }
}

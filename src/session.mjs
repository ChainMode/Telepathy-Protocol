import {
  createTpError,
  parseTpVersion,
  validateFayIdentity,
  sha256Digest
} from "./envelope.mjs";

const TRANSPORT_PRIORITY = [
  "dtp_tunnel",
  "native_tp",
  "a2a_jsonrpc",
  "mcp_tool_call",
  "rest_api",
  "prompt_embedding"
];

const SECURITY_RANK = {
  basic: 1,
  standard: 2,
  high: 3
};

function selectMutualOntology(initOntologies = [], respOntologies = []) {
  for (const a of initOntologies) {
    const match = respOntologies.find(
      (b) =>
        b.ontology_id === a.ontology_id &&
        b.version === a.version &&
        b.codebook_digest === a.codebook_digest
    );
    if (match) {
      const maxLoss =
        typeof a.max_quantization_loss === "number" && typeof match.max_quantization_loss === "number"
          ? Math.min(a.max_quantization_loss, match.max_quantization_loss)
          : a.max_quantization_loss ?? match.max_quantization_loss;
      const descriptor = {
        ontology_id: a.ontology_id,
        version: a.version,
        codebook_digest: a.codebook_digest
      };
      if (maxLoss !== undefined) descriptor.max_quantization_loss = maxLoss;
      return descriptor;
    }
  }
  return undefined;
}

export function checkModelHomogeneity(attA, attB) {
  if (!attA || !attB) return false;
  return (
    typeof attA.base_model_digest === "string" &&
    attA.base_model_digest === attB.base_model_digest &&
    typeof attA.adapter_digest === "string" &&
    attA.adapter_digest === attB.adapter_digest &&
    Number.isInteger(attA.dimension) &&
    attA.dimension > 0 &&
    attA.dimension === attB.dimension
  );
}

/**
 * Negotiates a ProtocolContract binding wire version, crypto_suite, transport,
 * and the TP 1.0 3-layer Normative Core (shared ontology -> tier_1_native_tp,
 * or ontology mismatch -> mandatory seamless tier_3_structured_text_fallback).
 * Per OQ-9, tier_2_ai_generated is disabled by default unless both sides opt in.
 */
export function negotiateProtocolContract(initiatorOffer, responderOffer, options = {}) {
  const vInit = parseTpVersion(initiatorOffer?.tp_version ?? "1.0");
  if (!vInit.ok) return vInit;
  const vResp = parseTpVersion(responderOffer?.tp_version ?? "1.0");
  if (!vResp.ok) return vResp;

  const negotiatedMinor = Math.min(vInit.minor, vResp.minor);
  const tpVersion = `1.${negotiatedMinor}`;

  // Crypto suite negotiation (Ed25519 MTI; ML-DSA-65 slot if both explicitly opt into PQ experimental)
  const initSuites = initiatorOffer?.crypto_suites ?? ["Ed25519"];
  const respSuites = responderOffer?.crypto_suites ?? ["Ed25519"];
  let cryptoSuite = null;
  if (
    options.allowPostQuantumExperimental === true &&
    initSuites.includes("ML-DSA-65") &&
    respSuites.includes("ML-DSA-65")
  ) {
    cryptoSuite = "ML-DSA-65";
  } else if (initSuites.includes("Ed25519") && respSuites.includes("Ed25519")) {
    cryptoSuite = "Ed25519";
  }
  if (!cryptoSuite) {
    return {
      ok: false,
      error: createTpError("TP-NEG004", "No mutually supported crypto_suite found during handshake.")
    };
  }

  // Transport method negotiation by priority order
  const initTransports = initiatorOffer?.transports ?? [];
  const respTransports = responderOffer?.transports ?? [];
  let selectedTransport = null;
  for (const proto of TRANSPORT_PRIORITY) {
    const a = initTransports.find((t) => t.protocol === proto);
    const b = respTransports.find((t) => t.protocol === proto);
    if (a && b) {
      if (proto === "dtp_tunnel" && a.tunnel_id && b.tunnel_id && a.tunnel_id !== b.tunnel_id) {
        continue;
      }
      selectedTransport = {
        protocol: proto,
        ...(a.endpoint || b.endpoint ? { endpoint: b.endpoint ?? a.endpoint } : {}),
        ...(a.tunnel_id || b.tunnel_id ? { tunnel_id: b.tunnel_id ?? a.tunnel_id } : {}),
        version: tpVersion
      };
      break;
    }
  }
  if (!selectedTransport) {
    return {
      ok: false,
      error: createTpError("TP-NEG001", "No mutually supported TransportMethod between Fays.")
    };
  }

  // CommunicationTier + Ontology Negotiation (OQ-1 & OQ-9)
  const sharedOntology = selectMutualOntology(
    initiatorOffer?.supported_ontologies,
    responderOffer?.supported_ontologies
  );

  const allowTier2 =
    options.allowExperimentalTier2 === true &&
    initiatorOffer?.allowExperimentalTier2 === true &&
    responderOffer?.allowExperimentalTier2 === true;

  const initTiers = initiatorOffer?.requested_tiers ?? [
    "tier_1_native_tp",
    "tier_3_structured_text_fallback"
  ];
  const respTiers = responderOffer?.requested_tiers ?? [
    "tier_1_native_tp",
    "tier_3_structured_text_fallback"
  ];

  let communicationTier = null;
  let fallbackActive = false;

  if (
    sharedOntology &&
    initTiers.includes("tier_1_native_tp") &&
    respTiers.includes("tier_1_native_tp")
  ) {
    communicationTier = "tier_1_native_tp";
    fallbackActive = false;
  } else if (
    allowTier2 &&
    initTiers.includes("tier_2_ai_generated") &&
    respTiers.includes("tier_2_ai_generated")
  ) {
    communicationTier = "tier_2_ai_generated";
    fallbackActive = false;
  } else {
    const initAllowsFallback = initiatorOffer?.mandatoryFallbackSupported !== false;
    const respAllowsFallback = responderOffer?.mandatoryFallbackSupported !== false;
    if (!initAllowsFallback || !respAllowsFallback) {
      return {
        ok: false,
        error: createTpError(
          "TP-NEG002",
          "No shared ontology or enabled normative tier; tier_2_ai_generated is disabled by default per OQ-9 and fallback was disabled."
        )
      };
    }
    communicationTier = "tier_3_structured_text_fallback";
    fallbackActive = true;
  }

  const experimentalLatentEnabled = Boolean(
    initiatorOffer?.allowExperimentalLatent === true &&
      responderOffer?.allowExperimentalLatent === true &&
      checkModelHomogeneity(
        initiatorOffer?.experimental_model_attestation,
        responderOffer?.experimental_model_attestation
      )
  );

  const nowIso = options.now ?? new Date().toISOString();
  const expMs = Date.parse(nowIso) + (options.ttlMs ?? 3600_000);
  const contractExpiration = new Date(expMs).toISOString();

  const secA = initiatorOffer?.security_level ?? "standard";
  const secB = responderOffer?.security_level ?? "standard";
  const securityLevel = (SECURITY_RANK[secA] ?? 2) >= (SECURITY_RANK[secB] ?? 2) ? secA : secB;

  const contractSeed = {
    initiator: initiatorOffer?.fay_id ?? "unknown",
    responder: responderOffer?.fay_id ?? "unknown",
    nowIso,
    transport: selectedTransport.protocol,
    tier: communicationTier
  };
  const contractId = `contract_${sha256Digest(contractSeed).slice(7, 23)}`;

  const contract = {
    contract_id: contractId,
    tp_version: tpVersion,
    crypto_suite: cryptoSuite,
    transport_method: selectedTransport,
    communication_tier: communicationTier,
    ...(sharedOntology ? { shared_ontology: sharedOntology } : {}),
    fallback_active: fallbackActive,
    experimental_latent_enabled: experimentalLatentEnabled,
    security_level: securityLevel,
    contract_expiration: contractExpiration,
    negotiation_trace: [
      {
        step: 1,
        initiator_fay_id: initiatorOffer?.fay_id ?? "ifay_unknown234567890",
        proposed: initTransports,
        selected: selectedTransport,
        timestamp: nowIso
      }
    ]
  };

  return { ok: true, contract };
}

function validateStructuredFallbackFrame(frame) {
  if (
    !frame ||
    frame.frame_type !== "structured_text_fallback" ||
    typeof frame.frame_id !== "string" ||
    frame.frame_id.length === 0 ||
    !["ontology_mismatch", "low_confidence", "unsupported_projection", "explicit_request"].includes(
      frame.fallback_reason
    ) ||
    typeof frame.language !== "string" ||
    frame.language.length < 2 ||
    typeof frame.intent_summary !== "string" ||
    frame.intent_summary.trim().length === 0 ||
    typeof frame.auditable_text !== "string" ||
    frame.auditable_text.trim().length === 0 ||
    !frame.structured_sections ||
    typeof frame.structured_sections.intent !== "string" ||
    frame.structured_sections.intent.trim().length === 0 ||
    typeof frame.structured_sections.context !== "string" ||
    !Array.isArray(frame.structured_sections.constraints) ||
    typeof frame.structured_sections.expected_outcome !== "string"
  ) {
    return {
      ok: false,
      error: createTpError("TP-COG003", "Malformed structured_text_fallback frame.")
    };
  }
  return { ok: true, mode: "normative_fallback" };
}

/**
 * Validates cognitive frame exchange against the negotiated ProtocolContract:
 * - Normative Layer 1: explicit_cognitive_frame (requires matching shared_ontology + confidence >= minConfidence)
 * - Normative Layer 3: structured_text_fallback (always accepted when well-formed)
 * - Experimental Research Track: experimental_latent_frame (requires contract.experimental_latent_enabled,
 *   identical cryptographic base_model_digest + adapter_digest, non-empty audit_summary, and fallback_frame)
 */
export function validateCognitiveFrameExchange(frame, contract, options = {}) {
  const minConfidence = options.minConfidence ?? 0.6;
  if (!frame || typeof frame !== "object") {
    return {
      ok: false,
      error: createTpError("TP-COG003", "Cognitive frame must be an object.")
    };
  }

  if (frame.frame_type === "structured_text_fallback") {
    return validateStructuredFallbackFrame(frame);
  }

  if (frame.frame_type === "explicit_cognitive_frame") {
    if (
      !contract?.shared_ontology ||
      contract.fallback_active === true ||
      frame.ontology_id !== contract.shared_ontology.ontology_id ||
      frame.ontology_version !== contract.shared_ontology.version
    ) {
      return {
        ok: false,
        requiresFallback: true,
        error: createTpError(
          "TP-COG001",
          "Ontology mismatch or fallback_active contract: sender MUST use structured_text_fallback."
        )
      };
    }
    if (typeof frame.confidence !== "number" || frame.confidence < minConfidence || frame.confidence > 1) {
      return {
        ok: false,
        requiresFallback: true,
        error: createTpError(
          "TP-COG002",
          `CognitiveFrame confidence (${frame.confidence}) below threshold (${minConfidence}); downgrade to structured_text_fallback.`
        )
      };
    }
    return { ok: true, mode: "normative_explicit" };
  }

  if (frame.frame_type === "experimental_latent_frame") {
    if (frame.experimental !== true || contract?.experimental_latent_enabled !== true) {
      return {
        ok: false,
        error: createTpError(
          "TP-LAT001",
          "ExperimentalLatentFrame rejected: experimental research track was not mutually enabled in ProtocolContract."
        )
      };
    }
    if (!checkModelHomogeneity(frame.sender_model_attestation, frame.receiver_model_attestation)) {
      return {
        ok: false,
        error: createTpError(
          "TP-LAT002",
          "Heterogeneous model raw latent vector transfer is scientifically unverified and forbidden in TP/1.0: base_model_digest, adapter_digest, and dimension MUST match identically."
        )
      };
    }
    if (typeof frame.audit_summary !== "string" || frame.audit_summary.trim().length === 0) {
      return {
        ok: false,
        error: createTpError(
          "TP-LAT003",
          "ExperimentalLatentFrame rejected: non-empty human-auditable audit_summary is mandatory."
        )
      };
    }
    const fbCheck = validateStructuredFallbackFrame(frame.fallback_frame);
    if (!fbCheck.ok) {
      return {
        ok: false,
        error: createTpError(
          "TP-LAT003",
          "ExperimentalLatentFrame rejected: valid structured_text_fallback fallback_frame is mandatory."
        )
      };
    }
    return { ok: true, mode: "experimental_homogeneous_latent" };
  }

  return {
    ok: false,
    error: createTpError("TP-COG003", `Unknown cognitive frame_type "${frame.frame_type}".`)
  };
}

/**
 * 5-Step TP Session Establishment State Machine:
 * Step 1: Protocol Negotiation (awaiting_negotiation -> negotiated)
 * Step 2: Mutual Identity Verification (negotiated -> identity_verified)
 * Step 3: FayProfile Exchange (identity_verified -> profiles_exchanged)
 * Step 4: Initial SharedContext Establishment (profiles_exchanged -> context_established)
 * Step 5: Session Ready for Goal & Cognitive Frame Exchange (context_established -> ready)
 */
export class SessionStateMachine {
  constructor({ timeoutMs = 30_000, startTimeMs = Date.now() } = {}) {
    this.timeoutMs = timeoutMs;
    this.startTimeMs = startTimeMs;
    this.step = 0;
    this.state = "awaiting_negotiation";
    this.contract = null;
    this.initiatorIdentity = null;
    this.responderIdentity = null;
    this.initiatorProfile = null;
    this.responderProfile = null;
    this.initialContext = null;
    this.lastError = null;
  }

  #halt(error) {
    this.state = "halted";
    this.lastError = error;
    return { ok: false, error };
  }

  #checkTimeout(nowMs) {
    if (nowMs !== undefined && nowMs - this.startTimeMs > this.timeoutMs) {
      return this.#halt(createTpError("TP-SES002", "Session establishment timed out."));
    }
    return null;
  }

  completeNegotiation(initiatorOffer, responderOffer, nowMs = undefined, negotiationOptions = {}) {
    if (this.state === "halted") return { ok: false, error: this.lastError };
    const to = this.#checkTimeout(nowMs);
    if (to) return to;
    if (this.step !== 0) {
      return this.#halt(createTpError("TP-SES001", `Step 1 negotiation invalid at step ${this.step}.`));
    }
    const res = negotiateProtocolContract(initiatorOffer, responderOffer, negotiationOptions);
    if (!res.ok) return this.#halt(res.error);
    this.contract = res.contract;
    this.step = 1;
    this.state = "negotiated";
    return { ok: true, contract: this.contract };
  }

  verifyIdentities(initiatorIdentity, responderIdentity, nowMs = undefined) {
    if (this.state === "halted") return { ok: false, error: this.lastError };
    const to = this.#checkTimeout(nowMs);
    if (to) return to;
    if (this.step !== 1) {
      return this.#halt(createTpError("TP-SES001", `Step 2 identity verification requires step 1, got step ${this.step}.`));
    }
    const initCheck = validateFayIdentity(initiatorIdentity);
    if (!initCheck.ok) return this.#halt(initCheck.error);
    const respCheck = validateFayIdentity(responderIdentity);
    if (!respCheck.ok) return this.#halt(respCheck.error);

    this.initiatorIdentity = initiatorIdentity;
    this.responderIdentity = responderIdentity;
    this.step = 2;
    this.state = "identity_verified";
    return { ok: true };
  }

  exchangeProfiles(initiatorProfile, responderProfile, nowMs = undefined) {
    if (this.state === "halted") return { ok: false, error: this.lastError };
    const to = this.#checkTimeout(nowMs);
    if (to) return to;
    if (this.step !== 2) {
      return this.#halt(createTpError("TP-SES001", `Step 3 profile exchange requires step 2, got step ${this.step}.`));
    }
    for (const prof of [initiatorProfile, responderProfile]) {
      if (
        !prof ||
        !prof.identity ||
        !Array.isArray(prof.capabilities) ||
        !prof.sharing_willingness ||
        !prof.status ||
        !prof.prime_authorization ||
        typeof prof.prime_authorization.fp_authorization_ref !== "string" ||
        prof.prime_authorization.fp_authorization_ref.length === 0
      ) {
        return this.#halt(
          createTpError("TP-ID003", "FayProfile missing mandatory PrimeAuthorization.fp_authorization_ref or fields.")
        );
      }
    }
    this.initiatorProfile = initiatorProfile;
    this.responderProfile = responderProfile;
    this.step = 3;
    this.state = "profiles_exchanged";
    return { ok: true };
  }

  establishInitialContext(contextSummary, nowMs = undefined) {
    if (this.state === "halted") return { ok: false, error: this.lastError };
    const to = this.#checkTimeout(nowMs);
    if (to) return to;
    if (this.step !== 3) {
      return this.#halt(createTpError("TP-SES001", `Step 4 context establishment requires step 3, got step ${this.step}.`));
    }
    if (!contextSummary || typeof contextSummary.context_id !== "string" || contextSummary.state !== "active") {
      return this.#halt(createTpError("TP-CTX001", "Initial SharedContext must be active with a valid context_id."));
    }
    this.initialContext = contextSummary;
    this.step = 4;
    this.state = "context_established";
    return { ok: true };
  }

  markReady(nowMs = undefined) {
    if (this.state === "halted") return { ok: false, error: this.lastError };
    const to = this.#checkTimeout(nowMs);
    if (to) return to;
    if (this.step !== 4) {
      return this.#halt(createTpError("TP-SES001", `Step 5 session_ready requires step 4, got step ${this.step}.`));
    }
    this.step = 5;
    this.state = "ready";
    return { ok: true };
  }

  static resumeFromCachedContract({
    contract,
    initiatorIdentity,
    responderIdentity,
    initiatorProfile,
    responderProfile,
    nowIso = new Date().toISOString()
  }) {
    if (!contract || Date.parse(nowIso) >= Date.parse(contract.contract_expiration)) {
      return {
        ok: false,
        error: createTpError("TP-SES003", "Cached ProtocolContract is missing or expired; full 5-step handshake required.")
      };
    }
    const initOk = validateFayIdentity(initiatorIdentity);
    if (!initOk.ok) return initOk;
    const respOk = validateFayIdentity(responderIdentity);
    if (!respOk.ok) return respOk;

    const sm = new SessionStateMachine();
    sm.contract = contract;
    sm.initiatorIdentity = initiatorIdentity;
    sm.responderIdentity = responderIdentity;
    sm.initiatorProfile = initiatorProfile;
    sm.responderProfile = responderProfile;
    sm.step = 3;
    sm.state = "profiles_exchanged";
    return { ok: true, session: sm };
  }
}

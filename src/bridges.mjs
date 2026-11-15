import {
  createTpError,
  canonicalizeJcs,
  sha256Digest,
  validateFayId
} from "./envelope.mjs";
import {
  validateSafeReferenceUri,
  encryptPayload
} from "./shared-context.mjs";

/**
 * 1. Faying Protocol (FP) Bridge: verifies fp_authorization_ref binding against Faying Mandate registry.
 */
export function verifyFayingMandateBinding(
  identityOrAuth,
  mandateRegistry,
  requiredOperation = undefined,
  nowIso = new Date().toISOString()
) {
  const fpRef = identityOrAuth?.fp_authorization_ref;
  if (typeof fpRef !== "string" || fpRef.length === 0) {
    return {
      ok: false,
      error: createTpError("TP-FP001", "Missing mandatory fp_authorization_ref Faying Mandate binding.")
    };
  }
  const mandate = mandateRegistry instanceof Map ? mandateRegistry.get(fpRef) : mandateRegistry?.[fpRef];
  if (!mandate) {
    return {
      ok: false,
      error: createTpError("TP-FP001", `Faying Mandate "${fpRef}" not found in verification registry.`)
    };
  }
  if (mandate.revoked === true) {
    return {
      ok: false,
      error: createTpError("TP-FP001", `Faying Mandate "${fpRef}" has been revoked by the Human Prime.`)
    };
  }
  if (mandate.expires_at && Date.parse(nowIso) >= Date.parse(mandate.expires_at)) {
    return {
      ok: false,
      error: createTpError("TP-FP001", `Faying Mandate "${fpRef}" expired at ${mandate.expires_at}.`)
    };
  }
  if (identityOrAuth.fay_id && mandate.fay_id && identityOrAuth.fay_id !== mandate.fay_id) {
    return {
      ok: false,
      error: createTpError("TP-FP001", "Faying Mandate fay_id mismatch.")
    };
  }
  if (identityOrAuth.human_prime_id && mandate.human_prime_id && identityOrAuth.human_prime_id !== mandate.human_prime_id) {
    return {
      ok: false,
      error: createTpError("TP-FP001", "Faying Mandate human_prime_id mismatch.")
    };
  }
  if (
    requiredOperation &&
    Array.isArray(mandate.allowed_operations) &&
    !mandate.allowed_operations.includes(requiredOperation)
  ) {
    return {
      ok: false,
      error: createTpError(
        "TP-FP001",
        `Faying Mandate "${fpRef}" does not authorize operation "${requiredOperation}".`
      )
    };
  }
  return { ok: true, mandate };
}

/**
 * 2. Control Authority Protocol (CAP) Bridge: builds a CAP 1.0 evaluation handoff for Host terminal device actions.
 * Note: Host refers strictly to the hardware/software terminal device (host_device_id), never the Human Prime.
 */
export function buildCapControlHandoff({
  goal,
  sender,
  hostDeviceId,
  capabilityId,
  accessMode = "execute",
  criticality = "sensitive",
  fayingGrade = "G2"
}) {
  if (!sender?.fp_authorization_ref) {
    return {
      ok: false,
      error: createTpError("TP-CAP001", "CAP device control handoff requires sender.fp_authorization_ref.")
    };
  }
  if (!hostDeviceId || typeof hostDeviceId !== "string") {
    return {
      ok: false,
      error: createTpError("TP-CAP001", "CAP handoff requires terminal device identifier hostDeviceId.")
    };
  }

  const capRequest = {
    protocol: { name: "CAP", version: "1.0" },
    request_id: `cap_req_${goal.goal_id}`,
    tp_goal_id: goal.goal_id,
    actor_fay_id: sender.fay_id,
    ...(sender.human_prime_id ? { human_prime_id: sender.human_prime_id } : {}),
    fp_authorization_ref: sender.fp_authorization_ref,
    faying_grade: fayingGrade,
    host_device_id: hostDeviceId,
    capability_id: capabilityId,
    access_mode: accessMode,
    declared_criticality: criticality,
    parameters: goal.parameters?.values ?? {}
  };
  const capHandoffRef = `cap://1.0/${capRequest.request_id}#${sha256Digest(capRequest).slice(7, 23)}`;
  return {
    ok: true,
    capHandoffRef,
    capRequest,
    updatedGoal: {
      ...structuredClone(goal),
      cap_handoff_ref: capHandoffRef
    }
  };
}

/**
 * 3. Data Tunnel Protocol (DTP) Bridge: binds TP transport to a DTP encrypted tunnel and maps large DTP streams
 * to CognitiveResources without duplicating byte-level compression inside TP (OQ-18).
 */
export function bindDtpTunnelTransport({ tunnelId, endpoint = undefined, version = "1.0" }) {
  if (typeof tunnelId !== "string" || tunnelId.trim().length === 0) {
    return {
      ok: false,
      error: createTpError("TP-DTP001", "bindDtpTunnelTransport requires a non-empty tunnelId.")
    };
  }
  return {
    ok: true,
    transportMethod: {
      protocol: "dtp_tunnel",
      tunnel_id: tunnelId,
      ...(endpoint ? { endpoint } : {}),
      version
    }
  };
}

export function dtpFragmentToCognitiveResource({
  tunnelId,
  streamId,
  contentType,
  totalBytes,
  sha256Checksum,
  resourceId,
  ownerFayId,
  resourceType = "memory_fragment",
  schemaRef,
  visibility = "shared",
  requiresEncryption = true,
  timestamp = new Date().toISOString()
}) {
  const ownerCheck = validateFayId(ownerFayId);
  if (!ownerCheck.ok) return ownerCheck;
  if (!tunnelId || !Number.isInteger(streamId) || streamId < 1) {
    return { ok: false, error: createTpError("TP-DTP001", "Invalid DTP tunnelId or streamId.") };
  }
  return {
    ok: true,
    resource: {
      resource_id: resourceId,
      resource_type: resourceType,
      content_ref: {
        mode: "dtp_tunnel",
        tunnel_id: tunnelId,
        stream_id: streamId,
        content_type: contentType,
        size_bytes: totalBytes,
        ...(sha256Checksum ? { checksum: sha256Checksum } : {})
      },
      access_policy: {
        owner_fay_id: ownerFayId,
        visibility,
        requires_encryption: requiresEncryption
      },
      schema_ref: schemaRef,
      metadata: {
        created_at: timestamp,
        updated_at: timestamp,
        version: 1,
        description: "Mounted over Data Tunnel Protocol (DTP) stream; byte compression delegated to DTP."
      }
    }
  };
}

/**
 * 4. Skill Sharing Protocol (SSP) Bridge: SSP serves as the network skill discovery authority (OQ-17).
 * Maps SSP Skill Descriptors into TP CapabilityDescriptors and matches by canonical JSON Schema equality.
 */
export function sspSkillDescriptorToCapability(sspSkill) {
  const accessMap = {
    public: "public",
    authenticated: "authenticated",
    authorized: "authorized",
    prime_delegated: "prime_delegated"
  };
  return {
    capability_id: sspSkill.skill_id,
    name: sspSkill.name,
    version: sspSkill.version ?? "1.0.0",
    input_schema: structuredClone(sspSkill.input_schema ?? { type: "object" }),
    output_schema: structuredClone(sspSkill.output_schema ?? { type: "object" }),
    access_level: accessMap[sspSkill.visibility] ?? "authorized",
    ssp_skill_ref: sspSkill.skill_id,
    ...(sspSkill.description ? { description: sspSkill.description } : {}),
    ...(Array.isArray(sspSkill.tags) ? { tags: [...sspSkill.tags] } : {})
  };
}

function normalizeSchemaForComparison(schema) {
  if (Array.isArray(schema)) {
    return schema.map(normalizeSchemaForComparison);
  }
  if (schema && typeof schema === "object") {
    const out = {};
    for (const k of Object.keys(schema).sort()) {
      if (k === "required" && Array.isArray(schema[k])) {
        out[k] = [...schema[k]].sort();
      } else {
        out[k] = normalizeSchemaForComparison(schema[k]);
      }
    }
    return out;
  }
  return schema;
}

export function matchCapabilitiesByExactSchema(capabilities, desiredInputSchema, desiredOutputSchema) {
  const targetIn = canonicalizeJcs(normalizeSchemaForComparison(desiredInputSchema));
  const targetOut = canonicalizeJcs(normalizeSchemaForComparison(desiredOutputSchema));
  return capabilities.filter((cap) => {
    const capIn = canonicalizeJcs(normalizeSchemaForComparison(cap.input_schema));
    const capOut = canonicalizeJcs(normalizeSchemaForComparison(cap.output_schema));
    return capIn === targetIn && capOut === targetOut;
  });
}

/**
 * 5. iFay Context Protocol (ICP) Bridge: attaches lossless .ctx annotations and enforces encryption
 * whenever ICP privacy_tier is "secret" or "confidential".
 */
export function icpCtxTurnToTpEnvelopePayload(icpTurn, encryptionContext = null) {
  if (!icpTurn || typeof icpTurn !== "object") {
    return { ok: false, error: createTpError("TP-ICP001", "Invalid ICP .ctx turn object.") };
  }
  const requiresEncryption =
    icpTurn.privacy_tier === "secret" || icpTurn.privacy_tier === "confidential";

  const icpAnnotations = {
    "@icp.turn_id": icpTurn.turn_id,
    "@icp.role": icpTurn.role,
    "@icp.privacy_tier": icpTurn.privacy_tier ?? "shared",
    ...(icpTurn.annotations ?? {})
  };

  if (requiresEncryption) {
    if (
      !encryptionContext ||
      !encryptionContext.senderPrivateKey ||
      !encryptionContext.receiverPublicKeyB64
    ) {
      return {
        ok: false,
        error: createTpError(
          "TP-ICP001",
          `ICP turn "${icpTurn.turn_id}" has privacy_tier="${icpTurn.privacy_tier}" and MUST be encrypted via EncryptedPayload.`
        )
      };
    }
    const enc = encryptPayload(
      icpTurn.content,
      encryptionContext.senderPrivateKey,
      encryptionContext.receiverPublicKeyB64,
      {
        auditRef: encryptionContext.auditRef ?? `aud_icp_${icpTurn.turn_id}`,
        disclosedFields: encryptionContext.disclosedFields
      }
    );
    if (!enc.ok) return enc;
    return {
      ok: true,
      payload: enc.encryptedPayload,
      icp_annotations: icpAnnotations
    };
  }

  return {
    ok: true,
    payload: structuredClone(icpTurn.content),
    icp_annotations: icpAnnotations
  };
}

/**
 * 6. External A2A Bridge: semantic-preserving TP Goal <-> A2A TaskCard / JSON-RPC 2.0 translation
 * with explicit LossMetadata (OQ-10) and hop_count <= 5 guard.
 */
export function tpGoalToA2ATaskCard(goal, sender, traceInfo = undefined) {
  const prevHops = traceInfo?.hop_count ?? 0;
  const nextHops = prevHops + 1;
  if (nextHops > 5) {
    return {
      ok: false,
      error: createTpError("TP-TRA001", `A2A translation hop_count (${nextHops}) exceeds maximum of 5.`)
    };
  }

  const droppedFields = [];
  const degradedSemantics = [];
  if (Array.isArray(goal.sub_goals) && goal.sub_goals.length > 0) {
    droppedFields.push("sub_goals");
    degradedSemantics.push("TP sub-goal DAG flattened to A2A TaskCard metadata extension.");
  }
  if (goal.context_ref) {
    droppedFields.push("context_ref");
    degradedSemantics.push("TP SharedContext mounting has no native A2A counterpart; preserved as reference ID only.");
  }

  const lossMetadata = {
    source_protocol: "TP/1.0",
    target_protocol: "a2a",
    dropped_fields: droppedFields,
    degraded_semantics: degradedSemantics,
    attribution_preserved: true,
    reversible: true
  };

  const nextTrace = {
    original_protocol: traceInfo?.original_protocol ?? "TP/1.0",
    original_message_id: traceInfo?.original_message_id ?? goal.goal_id,
    hop_count: nextHops,
    loss_metadata: lossMetadata
  };

  const taskCard = {
    id: goal.goal_id,
    status: { state: goal.status === "proposed" ? "submitted" : goal.status },
    description: goal.description.summary,
    input: goal.parameters.values,
    metadata: {
      tp_goal_type: goal.goal_type,
      tp_schema_ref: goal.parameters.schema_ref,
      tp_output_schema: goal.description.output_schema,
      tp_constraints: goal.constraints,
      tp_sender_fay_id: sender.fay_id,
      ...(sender.human_prime_id ? { tp_human_prime_id: sender.human_prime_id } : {}),
      tp_trace: nextTrace
    }
  };

  const jsonRpcRequest = {
    jsonrpc: "2.0",
    id: goal.goal_id,
    method: "tasks/send",
    params: taskCard
  };

  return {
    ok: true,
    taskCard,
    jsonRpcRequest,
    traceInfo: nextTrace,
    lossMetadata
  };
}

export function a2aTaskCardToTpGoal(taskCard, contextRef = "ctx_external_a2a") {
  if (!taskCard || typeof taskCard.id !== "string") {
    return { ok: false, error: createTpError("TP-TRA010", "Malformed A2A TaskCard.") };
  }
  const meta = taskCard.metadata ?? {};
  const prevTrace = meta.tp_trace;
  const nextHops = (prevTrace?.hop_count ?? 0) + 1;
  if (nextHops > 5) {
    return { ok: false, error: createTpError("TP-TRA001", "Hop count exceeded in A2A -> TP translation.") };
  }

  const lossMetadata = {
    source_protocol: "a2a",
    target_protocol: "TP/1.0",
    dropped_fields: [],
    degraded_semantics: meta.tp_goal_type
      ? []
      : ["Defaulted goal_type to execute because A2A TaskCard carries no native GoalType."],
    attribution_preserved: Boolean(meta.tp_sender_fay_id),
    reversible: true
  };

  return {
    ok: true,
    goal: {
      goal_id: taskCard.id,
      goal_type: meta.tp_goal_type ?? "execute",
      description: {
        summary: taskCard.description ?? `Imported A2A task ${taskCard.id}`,
        output_schema: meta.tp_output_schema ?? { type: "object" }
      },
      parameters: {
        schema_ref: meta.tp_schema_ref ?? "https://ifay.ai/schemas/a2a-generic.json",
        values: taskCard.input ?? {}
      },
      constraints: meta.tp_constraints ?? [],
      sub_goals: [],
      context_ref: contextRef,
      status: "proposed"
    },
    traceInfo: {
      original_protocol: prevTrace?.original_protocol ?? "a2a",
      original_message_id: prevTrace?.original_message_id ?? taskCard.id,
      hop_count: nextHops,
      loss_metadata: lossMetadata
    },
    lossMetadata
  };
}

/**
 * 7. External MCP Bridge: semantic-preserving TP CognitiveResource <-> MCP Resource translation
 * with SSRF URI validation and explicit LossMetadata.
 */
export function tpResourceToMcpResource(resource, sender, traceInfo = undefined) {
  const nextHops = (traceInfo?.hop_count ?? 0) + 1;
  if (nextHops > 5) {
    return { ok: false, error: createTpError("TP-TRA001", "MCP translation hop_count exceeded 5.") };
  }

  const ref = resource.content_ref;
  const uri =
    ref.mode === "reference"
      ? ref.uri
      : `https://tp-bridge.ifay.ai/inline/${encodeURIComponent(resource.resource_id)}`;

  const lossMetadata = {
    source_protocol: "TP/1.0",
    target_protocol: "mcp",
    dropped_fields: ["access_policy.requires_encryption"],
    degraded_semantics: [
      "TP fine-grained per-Fay ACL and SharedContext lifecycle are carried in MCP _meta annotations only."
    ],
    attribution_preserved: true,
    reversible: true
  };

  const mcpResource = {
    uri,
    name: resource.resource_id,
    mimeType: ref.content_type ?? "application/json",
    ...(ref.mode === "inline" ? { text: JSON.stringify(ref.data) } : {}),
    _meta: {
      tp_resource_id: resource.resource_id,
      tp_resource_type: resource.resource_type,
      tp_schema_ref: resource.schema_ref,
      tp_owner_fay_id: sender?.fay_id ?? resource.access_policy.owner_fay_id,
      tp_loss_metadata: lossMetadata,
      tp_hop_count: nextHops
    }
  };

  return { ok: true, mcpResource, lossMetadata };
}

export function mcpResourceToTpResource(mcpResource, ownerFayId, nowIso = new Date().toISOString()) {
  if (!mcpResource || typeof mcpResource.uri !== "string") {
    return { ok: false, error: createTpError("TP-TRA020", "Malformed MCP Resource.") };
  }
  const ownerOk = validateFayId(ownerFayId);
  if (!ownerOk.ok) return ownerOk;

  const meta = mcpResource._meta ?? {};
  let contentRef;
  if (typeof mcpResource.text === "string") {
    let parsedData = mcpResource.text;
    try {
      parsedData = JSON.parse(mcpResource.text);
    } catch {
      // keep raw text string
    }
    const sizeBytes = Buffer.byteLength(mcpResource.text, "utf8");
    contentRef = {
      mode: "inline",
      data: parsedData,
      size_bytes: sizeBytes
    };
  } else {
    const uriCheck = validateSafeReferenceUri(mcpResource.uri);
    if (!uriCheck.ok) return uriCheck;
    contentRef = {
      mode: "reference",
      uri: mcpResource.uri,
      content_type: mcpResource.mimeType ?? "application/octet-stream",
      size_bytes: mcpResource.size ?? 0
    };
  }

  const lossMetadata = {
    source_protocol: "mcp",
    target_protocol: "TP/1.0",
    dropped_fields: [],
    degraded_semantics: meta.tp_resource_type
      ? []
      : ["Defaulted resource_type to environment_context for external MCP resource."],
    attribution_preserved: true,
    reversible: true
  };

  return {
    ok: true,
    resource: {
      resource_id: meta.tp_resource_id ?? mcpResource.name ?? "res_mcp_imported",
      resource_type: meta.tp_resource_type ?? "environment_context",
      content_ref: contentRef,
      access_policy: {
        owner_fay_id: ownerFayId,
        visibility: "shared",
        requires_encryption: false
      },
      schema_ref: meta.tp_schema_ref ?? "https://ifay.ai/schemas/mcp-resource.json",
      metadata: {
        created_at: nowIso,
        updated_at: nowIso,
        version: 1
      }
    },
    lossMetadata
  };
}

/**
 * 8. Prompt Embedding Fallback Guard: rejects unencrypted confidential data (TP-TRA030)
 * and emits delimited, sanitized structured text with explicit LossMetadata.
 */
export function encodePromptEmbeddingEnvelope(envelope, options = {}) {
  if (options.containsConfidentialPlaintext === true) {
    return {
      ok: false,
      error: createTpError(
        "TP-TRA030",
        "Unencrypted confidential Human Prime data MUST NOT be serialized into prompt_embedding transport."
      )
    };
  }
  const lossMetadata = {
    source_protocol: "TP/1.0",
    target_protocol: "prompt_embedding",
    dropped_fields: ["signature"],
    degraded_semantics: ["Binary/cryptographic transport degraded to delimited structured prompt block."],
    attribution_preserved: true,
    reversible: false
  };
  const sanitizedJson = canonicalizeJcs({
    tp_version: "1.0",
    message_id: envelope.message_id,
    sender_fay_id: envelope.sender?.fay_id,
    receiver_fay_id: envelope.receiver?.fay_id,
    message_type: envelope.message_type,
    payload: envelope.payload,
    loss_metadata: lossMetadata
  }).replace(/<\/?TP_ENVELOPE>/gi, "");

  return {
    ok: true,
    promptBlock: `<TP_ENVELOPE version="1.0">${sanitizedJson}</TP_ENVELOPE>`,
    lossMetadata
  };
}

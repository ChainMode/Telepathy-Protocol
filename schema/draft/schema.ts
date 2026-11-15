// Copyright (c) iFay Contributors. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root.

/**
 * Telepathy Protocol (TP) 1.0 — TypeScript Type Definitions (Edition 2025-10-25)
 *
 * These types correspond 1-to-1 with the JSON Schema definitions in schemas/tp-1.0.json
 * and schema.json.
 *
 * Organized by:
 *   1. Primitives, Wire Version & Crypto Suites
 *   2. Identity Recognition Layer (身份辨识层)
 *   3. 3-Layer Cognitive Exchange Stack & Experimental Latent Research Track
 *   4. Cognitive Sharing Layer, Privacy, Credentials & Audit (认知分享层)
 *   5. Goal Negotiation Layer & Consultation (目标协商层)
 *   6. Protocol Negotiation & Loss Metadata (协议协商)
 *   7. Message Envelope & Error Handling (消息信封与错误处理)
 */

// ---------------------------------------------------------------------------
// 1. Primitives, Wire Version & Crypto Suites
// ---------------------------------------------------------------------------

/** Two-segment TP wire version ("1.0" or "TP/1.0"). Three-segment SemVer is rejected (TP-VER003). */
export type ProtocolVersion = string;

/** Canonical Fay identifier: ifay_<base32> or cofay_<base32>. */
export type FayID = string;

/** Negotiated envelope signature suite (Ed25519 MTI; ML-DSA-65 post-quantum agility slot). */
export type CryptoSuite = "Ed25519" | "ML-DSA-65";

/** Lowercase SHA-256 digest prefixed with "sha256:". */
export type Sha256Digest = string;

/** Opaque JSON Schema object. */
export type JSONSchema = Record<string, unknown>;

// ===========================================================================
// 2. Identity Recognition Layer (身份辨识层)
// ===========================================================================

export interface DIDProof {
  type: "Ed25519Signature2020" | "MLDSA65Signature2026" | "EcdsaSecp256k1Signature2019";
  created: string;
  verification_method: string;
  proof_value: string;
}

export interface DIDIdentifier {
  method: "did:key" | "did:web" | "did:chain";
  value: string;
  proof: DIDProof;
}

export interface FayIdentity {
  fay_id: FayID;
  fay_type: "iFay" | "coFay";
  human_prime_id?: string; // MUST be present when fay_type === "iFay"
  fp_authorization_ref?: string;
  did: DIDIdentifier;
}

export interface CapabilityDescriptor {
  capability_id: string;
  name: string;
  version: string;
  input_schema: JSONSchema;
  output_schema: JSONSchema;
  access_level: "public" | "authenticated" | "authorized" | "prime_delegated";
  ssp_skill_ref?: string;
  description?: string;
  tags?: string[];
}

export interface SharingWillingness {
  shareable_resource_types: CognitiveResourceType[];
  preferred_mode: "delegated_access" | "collaborative_space" | "both";
  max_concurrent_contexts: number;
}

export interface FayStatus {
  availability: "online" | "busy" | "away" | "offline";
  current_contexts: number;
  last_active: string;
}

export interface AuthorizationRestriction {
  restriction_type: string;
  description: string;
}

export interface PrimeAuthorization {
  fp_authorization_ref: string;
  authorized_resource_types: CognitiveResourceType[];
  authorized_operations: string[];
  max_sharing_duration: string;
  restrictions: AuthorizationRestriction[];
}

export interface OntologyDescriptor {
  ontology_id: string;
  version: string;
  codebook_digest: Sha256Digest;
  max_quantization_loss?: number;
}

export interface ModelHomogeneityAttestation {
  base_model_id: string;
  base_model_digest: Sha256Digest;
  adapter_digest: Sha256Digest;
  projection_version: string;
  dimension: number;
}

export interface FayProfile {
  identity: FayIdentity;
  capabilities: CapabilityDescriptor[];
  supported_ontologies?: OntologyDescriptor[];
  supported_crypto_suites?: CryptoSuite[];
  experimental_model_attestation?: ModelHomogeneityAttestation;
  sharing_willingness: SharingWillingness;
  status: FayStatus;
  prime_authorization: PrimeAuthorization;
  conformance_level?: "tp_core" | "tp_secure" | "tp_full";
  json_ld_context?: string;
}

// ===========================================================================
// 3. 3-Layer Cognitive Exchange Stack & Experimental Latent Research Track
// ===========================================================================

export interface CognitiveFrame {
  frame_type: "explicit_cognitive_frame";
  frame_id: string;
  ontology_id: string;
  ontology_version: string;
  intent_summary: string;
  confidence: number;
  assumptions: string[];
  constraints: string[];
  entities: Record<string, unknown>;
  context_refs: string[];
}

export interface StructuredTextFallbackFrame {
  frame_type: "structured_text_fallback";
  frame_id: string;
  fallback_reason: "ontology_mismatch" | "low_confidence" | "unsupported_projection" | "explicit_request";
  language: string;
  intent_summary: string;
  structured_sections: {
    intent: string;
    context: string;
    constraints: string[];
    expected_outcome: string;
  };
  auditable_text: string;
}

export interface ExperimentalLatentFrame {
  frame_type: "experimental_latent_frame";
  experimental: true;
  frame_id: string;
  sender_model_attestation: ModelHomogeneityAttestation;
  receiver_model_attestation: ModelHomogeneityAttestation;
  vector_encoding: "float16_base64" | "bfloat16_base64" | "int8_quantized_base64";
  vector_payload_b64: string;
  audit_summary: string;
  fallback_frame: StructuredTextFallbackFrame;
}

export type CognitiveExchangeFrame =
  | CognitiveFrame
  | StructuredTextFallbackFrame
  | ExperimentalLatentFrame;

// ===========================================================================
// 4. Cognitive Sharing Layer, Privacy, Credentials & Audit (认知分享层)
// ===========================================================================

export type CognitiveResourceType =
  | "memory_fragment"
  | "view_state"
  | "reasoning_engine"
  | "environment_context";

export interface InlineContent {
  mode: "inline";
  data: unknown;
  size_bytes: number; // <= 65536 (64 KiB)
}

export interface ReferenceContent {
  mode: "reference";
  uri: string; // https:// only, SSRF-guarded
  content_type: string;
  size_bytes: number;
  checksum?: Sha256Digest;
}

export interface DtpTunnelContent {
  mode: "dtp_tunnel";
  tunnel_id: string;
  stream_id: number;
  content_type: string;
  size_bytes: number;
  checksum?: Sha256Digest;
}

export interface ResourceAccessPolicy {
  owner_fay_id: FayID;
  visibility: "private" | "shared" | "public";
  requires_encryption: boolean;
}

export interface ResourceMetadata {
  created_at: string;
  updated_at: string;
  version: number;
  description?: string;
}

export interface CognitiveResource {
  resource_id: string;
  resource_type: CognitiveResourceType;
  content_ref: InlineContent | ReferenceContent | DtpTunnelContent;
  access_policy: ResourceAccessPolicy;
  schema_ref: string;
  metadata: ResourceMetadata;
}

export interface ResourceNotification {
  context_id: string;
  resource_id: string;
  resource_type: CognitiveResourceType;
  change_kind: "created" | "updated" | "unmounted";
  content_digest: Sha256Digest;
  byte_length: number;
  sync_version: number;
  updated_at: string;
  actor_fay_id: FayID;
}

export interface ResourcePermissions {
  [fay_id: string]: {
    read: boolean;
    write: boolean;
    time_limited?: string;
  };
}

export interface MountedResource {
  resource: CognitiveResource;
  mount_point: string;
  owner_fay_id: FayID;
  permissions: ResourcePermissions;
}

export interface AccessControlList {
  default_policy: "deny_all" | "read_only" | "read_write";
  per_resource_overrides: ResourcePermissions[];
}

export interface ContextLifecycle {
  state: "initializing" | "active" | "syncing" | "suspended" | "terminated";
  termination_reason?: "completed" | "expired" | "revoked";
  creation_time: string;
  expiration?: string;
  expiration_event?: string;
  revocation_reason?: string;
  last_state_change: string;
}

export interface SyncState {
  sync_version: number;
  updated_at: string;
  actor_fay_id: FayID;
  conflict_resolution: "last_writer_wins" | "crdt" | "operational_transform";
  pending_changes: number;
}

export interface SharedContext {
  context_id: string;
  participants: FayIdentity[];
  mode: "delegated_access" | "collaborative_space";
  mounted_resources: MountedResource[];
  access_control: AccessControlList;
  lifecycle: ContextLifecycle;
  sync_state: SyncState;
}

export interface KeyExchangeInfo {
  method: "ECDH-P256" | "X25519";
  public_key: string;
  encrypted_session_key: string;
  iv?: string;
  auth_tag?: string;
}

export interface SelectiveDisclosure {
  disclosed_fields: string[];
  redacted_field_digests?: Record<string, Sha256Digest>;
  policy_ref?: string;
}

export interface EncryptedPayload {
  encryption_algorithm: "AES-256-GCM" | "ChaCha20-Poly1305";
  encrypted_data: string;
  key_exchange_info: KeyExchangeInfo;
  selective_disclosure?: SelectiveDisclosure;
  audit_ref: string;
}

export interface CredentialScope {
  resources: string[];
  operations: string[];
  constraints?: Record<string, unknown>;
}

export interface CallbackCredential {
  credential_id: string;
  scope: CredentialScope;
  expiration: string;
  resource_reference: string;
  issuer_fay_id: FayID;
  holder_fay_id?: FayID;
  encrypted_token: string;
  revocation_endpoint?: string;
}

export interface CredentialRevocation {
  credential_id: string;
  issuer_fay_id: FayID;
  revoked_at: string;
  reason: string;
}

export interface AuditRecord {
  record_id: string;
  sequence: number;
  timestamp: string;
  event_type:
    | "session_established"
    | "context_created"
    | "context_synced"
    | "context_terminated"
    | "resource_mounted"
    | "resource_accessed"
    | "payload_encrypted"
    | "payload_decrypted"
    | "credential_issued"
    | "credential_used"
    | "credential_revoked"
    | "retention_compacted";
  actor_fay_id: FayID;
  human_prime_id?: string;
  context_id?: string;
  resource_id?: string;
  credential_id?: string;
  payload_digest: Sha256Digest;
  prev_record_hash: Sha256Digest;
  record_hash: Sha256Digest;
  retention_policy_ref?: string;
}

// ===========================================================================
// 5. Goal Negotiation Layer & Consultation (目标协商层)
// ===========================================================================

export type GoalType =
  | "query"
  | "execute"
  | "subscribe"
  | "notify"
  | "delegate"
  | "consult";

export type GoalStatus =
  | "proposed"
  | "negotiating"
  | "accepted"
  | "in_progress"
  | "completed"
  | "failed"
  | "cancelled"
  | "rejected";

export interface GoalDescription {
  summary: string;
  detailed?: string;
  output_schema: JSONSchema;
}

export interface TypedParameters {
  schema_ref: string;
  values: Record<string, unknown>;
}

export interface GoalConstraint {
  constraint_type: "deadline" | "priority" | "resource_limit" | "custom";
  value: unknown;
  required: boolean;
}

export interface SubGoalReference {
  sub_goal_id: string;
  depends_on: string[];
}

export interface GoalError {
  error_code: string;
  error_message: string;
  recovery_suggestions?: string[];
}

export interface GoalResult {
  goal_id: string;
  status: "completed" | "failed";
  output?: Record<string, unknown>;
  error?: GoalError;
}

export interface Goal {
  goal_id: string;
  goal_type: GoalType;
  description: GoalDescription;
  parameters: TypedParameters;
  constraints: GoalConstraint[];
  sub_goals: SubGoalReference[];
  context_ref: string;
  cap_handoff_ref?: string;
  status: GoalStatus;
  result?: GoalResult;
}

export interface PrimeDelegation {
  human_prime_id: string;
  delegated_permissions: string[];
  fp_authorization_ref: string;
}

export interface AuthorizationScope {
  required_permissions: string[];
  prime_delegation?: PrimeDelegation;
}

export interface RetryPolicy {
  max_retries: number;
  backoff_strategy: "fixed" | "exponential";
  initial_delay_ms: number;
}

export interface CallbackConfig {
  callback_url?: string;
  callback_credential?: CallbackCredential;
  timeout_ms: number;
  retry_policy?: RetryPolicy;
}

export interface ConsultationRequest {
  consultation_id: string;
  query_type: string;
  required_info_schema: JSONSchema;
  authorization_scope: AuthorizationScope;
  callback_config?: CallbackConfig;
  chained_from?: string;
}

export interface ConsultationResponse {
  consultation_id: string;
  status: "fulfilled" | "partial" | "rejected";
  data?: Record<string, unknown>;
  encrypted_payload?: EncryptedPayload;
  rejection_reason?: string;
}

// ===========================================================================
// 6. Protocol Negotiation & Loss Metadata (协议协商)
// ===========================================================================

export type CommunicationTier =
  | "tier_1_native_tp"
  | "tier_2_ai_generated"
  | "tier_3_structured_text_fallback";

export interface TransportMethod {
  protocol:
    | "native_tp"
    | "dtp_tunnel"
    | "a2a_jsonrpc"
    | "mcp_tool_call"
    | "rest_api"
    | "prompt_embedding";
  endpoint?: string;
  tunnel_id?: string;
  version?: string;
}

export interface NegotiationStep {
  step: number;
  initiator_fay_id: FayID;
  proposed: TransportMethod[];
  selected?: TransportMethod;
  timestamp: string;
}

export interface ProtocolContract {
  contract_id: string;
  tp_version: ProtocolVersion;
  crypto_suite: CryptoSuite;
  transport_method: TransportMethod;
  communication_tier: CommunicationTier;
  shared_ontology?: OntologyDescriptor;
  fallback_active: boolean;
  experimental_latent_enabled?: boolean;
  security_level: "basic" | "standard" | "high";
  contract_expiration: string;
  negotiation_trace: NegotiationStep[];
}

export interface LossMetadata {
  source_protocol: string;
  target_protocol: string;
  dropped_fields: string[];
  degraded_semantics: string[];
  attribution_preserved: boolean;
  reversible: boolean;
}

export interface TraceInfo {
  original_protocol: string;
  original_message_id: string;
  hop_count: number;
  loss_metadata?: LossMetadata;
}

// ===========================================================================
// 7. Message Envelope & Error Handling (消息信封与错误处理)
// ===========================================================================

export type MessageType =
  | "identity_proof"
  | "profile_exchange"
  | "context_create"
  | "context_update"
  | "context_sync"
  | "context_revoke"
  | "resource_mount"
  | "resource_unmount"
  | "resource_notify"
  | "cognitive_frame"
  | "credential_revoke"
  | "goal_propose"
  | "goal_negotiate"
  | "goal_accept"
  | "goal_reject"
  | "goal_result"
  | "consultation_request"
  | "consultation_response"
  | "negotiate_request"
  | "negotiate_response"
  | "session_ready"
  | "error";

export interface MessageEnvelope {
  tp_version: ProtocolVersion;
  message_id: string;
  sender: FayIdentity;
  receiver: FayIdentity;
  timestamp: string;
  message_type: MessageType;
  payload: unknown;
  correlation_id?: string;
  crypto_suite?: CryptoSuite;
  signature?: string;
  protocol_contract_ref?: string;
  icp_annotations?: Record<string, unknown>;
  trace_info?: TraceInfo;
}

export interface TPError {
  error_code: string;
  message: string;
  details?: Record<string, unknown>;
  recovery_suggestions?: string[];
  correlation_id?: string;
}

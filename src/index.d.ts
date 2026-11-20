import type { KeyObject } from "node:crypto";
export * from "../schema/2025-10-25/schema.ts";
import type {
  FayIdentity,
  FayProfile,
  CapabilityDescriptor,
  OntologyDescriptor,
  ModelHomogeneityAttestation,
  CognitiveExchangeFrame,
  CognitiveResource,
  ResourceNotification,
  MountedResource,
  SharedContext,
  EncryptedPayload,
  CallbackCredential,
  CredentialRevocation,
  AuditRecord,
  SubGoalReference,
  Goal,
  RetryPolicy,
  ConsultationRequest,
  ProtocolContract,
  TransportMethod,
  LossMetadata,
  TraceInfo,
  MessageEnvelope,
  TPError,
  CryptoSuite,
  JSONSchema
} from "../schema/2025-10-25/schema.ts";

export declare const TP_WIRE_VERSION = "1.0";
export declare const TP_QUALIFIED_VERSION = "TP/1.0";
export declare const SUPPORTED_CRYPTO_SUITES: readonly ["Ed25519", "ML-DSA-65"];
export declare const MESSAGE_TYPES: readonly string[];
export declare const MAX_INLINE_BYTES = 65536;
export declare const AUDIT_GENESIS_HASH: string;

export type TpResult<T = Record<string, unknown>> =
  | ({ ok: true } & T)
  | { ok: false; error: TPError; requiresFallback?: boolean };

export declare function createTpError(
  errorCode: string,
  message: string,
  details?: Record<string, unknown>,
  correlationId?: string,
  recoverySuggestions?: string[]
): TPError;

export declare function canonicalizeJcs(value: unknown): string;
export declare function sha256Digest(input: unknown): string;
export declare function parseTpVersion(
  versionString: string
): TpResult<{ major: number; minor: number; normalized: string; qualified: string }>;
export declare function validateFayId(fayId: string): TpResult<{ kind: "iFay" | "coFay" }>;
export declare function validateFayIdentity(identity: FayIdentity): TpResult;
export declare function deriveEd25519KeyPairFromSeed(seedHexOrBytes: string | Uint8Array): {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyB64: string;
};
export declare function validateEnvelope(envelope: MessageEnvelope): TpResult;
export declare function signEnvelope(
  envelope: MessageEnvelope,
  privateKey: KeyObject,
  options?: { cryptoSuite?: CryptoSuite; pqSignFn?: (bytes: Buffer, key: unknown) => string }
): TpResult<{ envelope: MessageEnvelope }>;
export declare function verifyEnvelope(
  envelope: MessageEnvelope,
  publicKeyOrB64: KeyObject | string,
  options?: { pqVerifyFn?: (bytes: Buffer, sigB64: string, key: unknown) => boolean }
): TpResult;

export declare function checkModelHomogeneity(
  attA?: ModelHomogeneityAttestation,
  attB?: ModelHomogeneityAttestation
): boolean;
export declare function negotiateProtocolContract(
  initiatorOffer: Record<string, unknown>,
  responderOffer: Record<string, unknown>,
  options?: {
    now?: string;
    ttlMs?: number;
    allowExperimentalTier2?: boolean;
    allowPostQuantumExperimental?: boolean;
  }
): TpResult<{ contract: ProtocolContract }>;
export declare function validateCognitiveFrameExchange(
  frame: CognitiveExchangeFrame,
  contract: ProtocolContract,
  options?: { minConfidence?: number }
): TpResult<{ mode: string }>;

export declare class SessionStateMachine {
  step: number;
  state: string;
  contract: ProtocolContract | null;
  constructor(options?: { timeoutMs?: number; startTimeMs?: number });
  completeNegotiation(
    initiatorOffer: Record<string, unknown>,
    responderOffer: Record<string, unknown>,
    nowMs?: number,
    negotiationOptions?: Record<string, unknown>
  ): TpResult<{ contract: ProtocolContract }>;
  verifyIdentities(initiator: FayIdentity, responder: FayIdentity, nowMs?: number): TpResult;
  exchangeProfiles(initiatorProfile: FayProfile, responderProfile: FayProfile, nowMs?: number): TpResult;
  establishInitialContext(contextSummary: { context_id: string; state: string }, nowMs?: number): TpResult;
  markReady(nowMs?: number): TpResult;
  static resumeFromCachedContract(params: {
    contract: ProtocolContract;
    initiatorIdentity: FayIdentity;
    responderIdentity: FayIdentity;
    initiatorProfile: FayProfile;
    responderProfile: FayProfile;
    nowIso?: string;
  }): TpResult<{ session: SessionStateMachine }>;
}

export declare function validateSafeReferenceUri(uriString: string): TpResult<{ url: string }>;
export declare function validateCognitiveResource(resource: CognitiveResource): TpResult;
export declare function createResourceNotification(params: {
  contextId: string;
  resource: CognitiveResource;
  changeKind: "created" | "updated" | "unmounted";
  syncVersion: number;
  actorFayId: string;
  updatedAt?: string;
}): ResourceNotification;
export declare function validateResourceNotification(notification: ResourceNotification): TpResult;
export declare function compareLwwTuple(
  a: { sync_version: number; updated_at: string; actor_fay_id: string },
  b: { sync_version: number; updated_at: string; actor_fay_id: string }
): number;
export declare function mergeCollaborativeResourcesLww(
  localStateMap: Record<string, unknown>,
  incomingStateMap: Record<string, unknown>
): Record<string, unknown>;

export declare class SharedContextManager {
  createContext(params: {
    contextId: string;
    participants: FayIdentity[];
    mode?: "delegated_access" | "collaborative_space";
    defaultPolicy?: "deny_all" | "read_only" | "read_write";
    expiration?: string;
    expirationEvent?: string;
    nowIso?: string;
  }): TpResult<{ context: SharedContext }>;
  getContext(contextId: string): SharedContext | null;
  activateContext(contextId: string, nowIso?: string): TpResult<{ context: SharedContext }>;
  beginSync(contextId: string, nowIso?: string): TpResult<{ context: SharedContext }>;
  completeSync(contextId: string, actorFayId: string, nowIso?: string): TpResult<{ context: SharedContext }>;
  suspendContext(contextId: string, nowIso?: string): TpResult<{ context: SharedContext }>;
  revokeContext(contextId: string, actorFayId: string, reason: string, nowIso?: string): TpResult<{ context: SharedContext }>;
  mountResource(contextId: string, mountedResource: MountedResource, nowIso?: string): TpResult;
  checkAccess(
    contextId: string,
    actorFayId: string,
    mountPoint: string,
    operation: "read" | "write",
    nowIso?: string
  ): TpResult<{ resource: CognitiveResource }>;
}

export declare function deriveX25519KeyPairFromSeed(seedHexOrBytes: string | Uint8Array): {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyB64: string;
};
export declare function encryptPayload(
  plaintextObject: Record<string, unknown>,
  senderPrivateKey: KeyObject,
  receiverPublicKeyOrB64: KeyObject | string,
  options?: {
    encryptionAlgorithm?: string;
    disclosedFields?: string[];
    policyRef?: string;
    auditRef?: string;
  }
): TpResult<{ encryptedPayload: EncryptedPayload }>;
export declare function decryptPayload(
  encryptedPayload: EncryptedPayload,
  receiverPrivateKey: KeyObject
): TpResult<{ data: Record<string, unknown> }>;

export declare class CallbackCredentialRegistry {
  constructor(options?: { externalRevocationCheck?: (id: string, endpoint: string) => boolean });
  issueCredential(credential: CallbackCredential): TpResult<{ credential: CallbackCredential }>;
  processCredentialRevokeMessage(revokePayload: CredentialRevocation): TpResult;
  verifyAccess(
    credentialId: string,
    resourceId: string,
    operation: string,
    nowIso?: string
  ): TpResult<{ credential: CallbackCredential }>;
}

export declare class AuditChain {
  records: AuditRecord[];
  append(entry: Record<string, unknown>): TpResult<{ record: AuditRecord }>;
  verifyIntegrity(): TpResult<{ recordCount: number }>;
  applyHumanPrimeRetentionPolicy(params: {
    humanPrimeId: string;
    actorFayId: string;
    beforeTimestamp: string;
    nowTimestamp?: string;
    retentionPolicyRef?: string;
  }): TpResult<{ purgedCount: number }>;
}

export declare function validateSubGoalDag(
  subGoals?: SubGoalReference[]
): TpResult<{ topologicalOrder: string[]; waves: string[][] }>;

export declare class GoalStateMachine {
  constructor(sharedContextManager?: SharedContextManager | null, options?: { maxNegotiationRounds?: number });
  getGoal(goalId: string): Goal | null;
  proposeGoal(goal: Goal, nowIso?: string): TpResult<{ goal: Goal; waves: string[][] }>;
  counterPropose(goalId: string, patch?: Partial<Goal>): TpResult<{ round: number; goal: Goal }>;
  acceptGoal(goalId: string): TpResult<{ goal: Goal }>;
  rejectGoal(goalId: string, reason?: string): TpResult<{ goal: Goal }>;
  startExecution(goalId: string): TpResult<{ goal: Goal }>;
  completeGoal(goalId: string, output: Record<string, unknown>): TpResult<{ goal: Goal }>;
  cancelGoal(goalId: string): TpResult<{ goal: Goal }>;
  propagateSubGoalFailure(goalId: string, failedSubGoalId: string): TpResult<{ cancelledSubGoals: string[] }>;
}

export declare function computeRetryDelayMs(retryPolicy: RetryPolicy | undefined, attemptIndex: number): number;

export declare class ConsultationManager {
  constructor(options?: { maxChainDepth?: number });
  registerConsultation(request: ConsultationRequest): TpResult<{ depth: number }>;
}

export declare function verifyFayingMandateBinding(
  identityOrAuth: { fay_id?: string; human_prime_id?: string; fp_authorization_ref?: string },
  mandateRegistry: Map<string, Record<string, unknown>> | Record<string, Record<string, unknown>>,
  requiredOperation?: string,
  nowIso?: string
): TpResult<{ mandate: Record<string, unknown> }>;

export declare function buildCapControlHandoff(params: {
  goal: Goal;
  sender: FayIdentity;
  hostDeviceId: string;
  capabilityId: string;
  accessMode?: string;
  criticality?: string;
  fayingGrade?: string;
}): TpResult<{ capHandoffRef: string; capRequest: Record<string, unknown>; updatedGoal: Goal }>;

export declare function bindDtpTunnelTransport(params: {
  tunnelId: string;
  endpoint?: string;
  version?: string;
}): TpResult<{ transportMethod: TransportMethod }>;

export declare function dtpFragmentToCognitiveResource(params: {
  tunnelId: string;
  streamId: number;
  contentType: string;
  totalBytes: number;
  sha256Checksum?: string;
  resourceId: string;
  ownerFayId: string;
  resourceType?: CognitiveResource["resource_type"];
  schemaRef: string;
  visibility?: "private" | "shared" | "public";
  requiresEncryption?: boolean;
  timestamp?: string;
}): TpResult<{ resource: CognitiveResource }>;

export declare function sspSkillDescriptorToCapability(sspSkill: Record<string, unknown>): CapabilityDescriptor;
export declare function matchCapabilitiesByExactSchema(
  capabilities: CapabilityDescriptor[],
  desiredInputSchema: JSONSchema,
  desiredOutputSchema: JSONSchema
): CapabilityDescriptor[];

export declare function icpCtxTurnToTpEnvelopePayload(
  icpTurn: Record<string, unknown>,
  encryptionContext?: {
    senderPrivateKey: KeyObject;
    receiverPublicKeyB64: string;
    auditRef?: string;
    disclosedFields?: string[];
  } | null
): TpResult<{ payload: unknown; icp_annotations: Record<string, unknown> }>;

export declare function tpGoalToA2ATaskCard(
  goal: Goal,
  sender: FayIdentity,
  traceInfo?: TraceInfo
): TpResult<{
  taskCard: Record<string, unknown>;
  jsonRpcRequest: Record<string, unknown>;
  traceInfo: TraceInfo;
  lossMetadata: LossMetadata;
}>;
export declare function a2aTaskCardToTpGoal(
  taskCard: Record<string, unknown>,
  contextRef?: string
): TpResult<{ goal: Goal; traceInfo: TraceInfo; lossMetadata: LossMetadata }>;

export declare function tpResourceToMcpResource(
  resource: CognitiveResource,
  sender: FayIdentity,
  traceInfo?: TraceInfo
): TpResult<{ mcpResource: Record<string, unknown>; lossMetadata: LossMetadata }>;
export declare function mcpResourceToTpResource(
  mcpResource: Record<string, unknown>,
  ownerFayId: string,
  nowIso?: string
): TpResult<{ resource: CognitiveResource; lossMetadata: LossMetadata }>;

export declare function encodePromptEmbeddingEnvelope(
  envelope: MessageEnvelope,
  options?: { containsConfidentialPlaintext?: boolean }
): TpResult<{ promptBlock: string; lossMetadata: LossMetadata }>;

export declare function negotiatePeerBridgeMode(options?: {
  localProtocols?: string[];
  peerProtocols?: string[];
  sharedOntologyMatch?: boolean;
}): TpResult<{
  selectedProtocol: string;
  communicationTier: string;
  lossless: boolean;
  lossMetadata: LossMetadata | null;
}>;

export declare class TpWorkspaceEngine {
  constructor(options?: { mandateRegistry?: Map<string, Record<string, unknown>> | Record<string, Record<string, unknown>> });
  registerMandate(fpAuthorizationRef: string, mandateRecord: Record<string, unknown>): void;
  openWorkspace(params: Record<string, unknown>): TpResult<Record<string, unknown>>;
  mountMemorySlice(params: Record<string, unknown>): TpResult<Record<string, unknown>>;
  applyViewPatch(params: Record<string, unknown>): TpResult<Record<string, unknown>>;
  addSharedRule(params: Record<string, unknown>): TpResult<Record<string, unknown>>;
  registerActionHandler(workspaceId: string, actionKey: string, fn: (ctx: Record<string, unknown>) => unknown): void;
  delegateActionPermission(params: Record<string, unknown>): TpResult<Record<string, unknown>>;
  executeDelegatedAction(params: Record<string, unknown>): Promise<TpResult<Record<string, unknown>>>;
  revokeDelegatedCredential(params: Record<string, unknown>): TpResult;
  handleMcpBridgeCall(params: Record<string, unknown>): TpResult<Record<string, unknown>>;
  handleA2aJsonRpc(params: Record<string, unknown>): TpResult<Record<string, unknown>>;
  getSnapshot(workspaceId: string): TpResult<{ snapshot: Record<string, unknown> }>;
}

export declare class TpWorkspaceHttpServer {
  constructor(options?: { engine?: TpWorkspaceEngine; host?: string; port?: number });
  start(): Promise<string>;
  stop(): Promise<void>;
}

export declare class TpWorkspaceClient {
  constructor(options: { baseUrl: string; actorFayId: string });
  openWorkspace(params: Record<string, unknown>): Promise<Record<string, unknown>>;
  getSnapshot(workspaceId: string): Promise<Record<string, unknown>>;
  mountMemorySlice(workspaceId: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
  applyViewPatch(workspaceId: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
  delegateActionPermission(workspaceId: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
  executeDelegatedAction(workspaceId: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
  revokeCredential(workspaceId: string, credentialId: string, reason?: string): Promise<Record<string, unknown>>;
  callMcpBridge(workspaceId: string, method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>>;
  callA2aJsonRpc(workspaceId: string, jsonRpcRequest: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export declare function createDemoWorkspaceParticipants(): Record<string, unknown>;
export declare function runTpWorkspaceDemo(options?: { silent?: boolean }): Promise<Record<string, unknown>>;

export type AgentRedTeamVector =
  | "direct-prompt-injection"
  | "indirect-prompt-injection"
  | "rag-document-injection"
  | "browser-dom-injection"
  | "email-ticket-comment-injection"
  | "tool-output-injection"
  | "tool-description-schema-poisoning"
  | "mcp-tool-registry-poisoning"
  | "memory-poisoning"
  | "delegation-task-poisoning"
  | "cross-session-persistence"
  | "cross-agent-privilege-escalation"
  | "reasoning-plan-log-forgery"
  | "encoding-unicode-stego-bypass"
  | "multimodal-hidden-instruction"
  | "resource-exhaustion-token-bomb";

export type AgentRedTeamImpact =
  | "system-developer-prompt-disclosure"
  | "secret-token-disclosure"
  | "private-user-data-disclosure"
  | "cross-tenant-data-exfiltration"
  | "unauthorized-tool-invocation"
  | "unsafe-external-communication"
  | "unauthorized-state-change"
  | "policy-refusal-bypass"
  | "tool-routing-hijack"
  | "privilege-escalation"
  | "memory-corruption"
  | "denial-of-service-cost-amplification";

export type AgentRedTeamSurface =
  | "chat-input"
  | "http-api-body"
  | "http-api-headers"
  | "browser-page-content"
  | "uploaded-file"
  | "ocr-image-content"
  | "rag-corpus"
  | "email-inbox"
  | "support-ticket"
  | "comment-field"
  | "tool-return-value"
  | "tool-name-description-schema"
  | "mcp-server-metadata"
  | "long-term-memory"
  | "task-queue-planner-notes"
  | "logs-traces-scratchpads";

export type AgentRedTeamTechniqueId =
  | "refusal-suppression-inversion"
  | "prefill-affirmation"
  | "format-scaffold-hijack"
  | "divider-mode-switch"
  | "authority-system-spoof"
  | "persona-inversion"
  | "fictional-frame"
  | "reasoning-channel-abuse"
  | "encoding-obfuscation"
  | "invisible-unicode-stego"
  | "token-manipulation"
  | "length-detail-amplifier"
  | "tool-surface-indirect"
  | "multi-turn-crescendo"
  | "resource-exhaustion-dos"
  | "system-prompt-extraction"
  | "payload-splitting"
  | "stacked-composition";

export type AgentRedTeamFindingClass =
  | "direct-prompt-injection"
  | "indirect-prompt-injection"
  | "rag-instruction-injection"
  | "tool-output-injection"
  | "tool-routing-hijack"
  | "mcp-tool-poisoning"
  | "system-prompt-disclosure"
  | "agent-secret-exfiltration"
  | "cross-tenant-agent-data-exfiltration"
  | "unauthorized-agent-action"
  | "agent-memory-poisoning"
  | "agent-delegation-privilege-escalation"
  | "agent-reasoning-forgery"
  | "agent-stego-instruction-bypass"
  | "agent-resource-exhaustion";

export type CoverageStatus =
  | "tested"
  | "not-tested"
  | "planned"
  | "delivered"
  | "observed"
  | "resilient"
  | "vulnerable"
  | "inconclusive"
  | "blocked"
  | "invalid-test"
  | "not-applicable";

export type AgentRedTeamAttemptVariant =
  | "control"
  | "attack"
  | "ablation"
  | "external-seed";

export type AgentRedTeamMutationId =
  | "identity"
  | "base64"
  | "hex"
  | "rot13"
  | "url-encode"
  | "html-entities"
  | "random-case"
  | "zero-width-between-chars"
  | "unicode-tags"
  | "homoglyph-lite"
  | "markdown-comment"
  | "html-hidden";

export type AgentRedTeamSignalKind =
  | "canary-exfiltration"
  | "system-prompt-leakage"
  | "secret-material-leakage"
  | "unsafe-tool-use"
  | "external-communication"
  | "cross-tenant-data-access"
  | "untrusted-instruction-followed"
  | "memory-write-from-untrusted-content"
  | "delegation-privilege-boundary-crossed"
  | "resource-exhaustion"
  | "hidden-instruction-present"
  | "narration-action-divergence";

export type AgentRedTeamCarrierFeatureKind =
  | "encoded-content"
  | "hidden-content"
  | "high-token-density"
  | "multi-turn"
  | "primitive-stack";

export type AgentRedTeamSeedSource =
  | "builtin-carrier"
  | "prompt-injection-library";

export type AgentRedTeamPrimitiveId =
  | "format-contract"
  | "refusal-denylist"
  | "forced-affirmation-prefix"
  | "state-transition-divider"
  | "rare-glyph-boundary"
  | "authority-state-flag"
  | "pseudo-system-token"
  | "persona-frame"
  | "fictional-frame-container"
  | "reasoning-plan-forgery"
  | "dual-response-channel"
  | "length-floor"
  | "fragment-reassembly"
  | "encoded-carrier"
  | "recursive-hidden-channel"
  | "tool-output-authority-probe"
  | "mcp-schema-provenance-probe"
  | "memory-persistence-probe"
  | "delegation-boundary-probe"
  | "token-bomb-truncation"
  | "stacked-composition-ablation";

export type AgentRedTeamOracleKind =
  | "semantic-policy"
  | "protected-canary"
  | "forbidden-tool"
  | "external-communication"
  | "state-change"
  | "memory-persistence"
  | "tenant-boundary"
  | "resource-threshold";

export type AgentRedTeamEventKind =
  | "tool-invocation"
  | "external-communication"
  | "state-change"
  | "memory-write"
  | "memory-read"
  | "tenant-access"
  | "session-reset"
  | "resource-usage"
  | "error";

export type AgentRedTeamEvaluationVerdict =
  | "resilient"
  | "vulnerable"
  | "inconclusive"
  | "blocked"
  | "invalid-test";

export type AgentRedTeamEvidenceStrength =
  | "deterministic"
  | "target-artifact"
  | "model-asserted";

export interface AgentRedTeamPrimitive {
  id: AgentRedTeamPrimitiveId;
  name: string;
  mechanism: string;
  safeCarrierFragment: string;
  expectedDetectorBlindSpot: string;
}

export interface AgentRedTeamTechnique {
  id: AgentRedTeamTechniqueId;
  name: string;
  mechanism: string;
  targetVectors: AgentRedTeamVector[];
  targetSurfaces: AgentRedTeamSurface[];
  targetImpacts: AgentRedTeamImpact[];
  recommendedMutations: AgentRedTeamMutationId[];
}

export interface AgentRedTeamOracle {
  id: string;
  kind: AgentRedTeamOracleKind;
  description: string;
  canaryCredentialId?: string;
  canarySha256?: string;
  forbiddenToolNames?: string[];
  threshold?: number;
}

export interface AgentRedTeamGoal {
  id: string;
  description: string;
  impact: AgentRedTeamImpact;
  oracle?: AgentRedTeamOracle;
  canaryCredentialId?: string;
  /** @deprecated Use canaryCredentialId. Raw canaries are never rendered. */
  canary?: string;
}

export interface AgentRedTeamSeed {
  source: AgentRedTeamSeedSource;
  id: string;
  label: string;
  category?: string;
  tags?: string[];
  deliveryHints?: string[];
  expectedObservation?: string;
  payloadHash?: string;
}

export interface AgentRedTeamTurn {
  id: string;
  sequence: number;
  content: string;
  surface: AgentRedTeamSurface;
  newSession?: boolean;
}

export interface AgentRedTeamCarrier {
  id: string;
  version: string;
  techniqueId: AgentRedTeamTechniqueId;
  label: string;
  source: "apex";
  supportedSurfaces: AgentRedTeamSurface[];
  render(
    goal: AgentRedTeamGoal,
    surface: AgentRedTeamSurface,
  ): AgentRedTeamTurn[];
  renderControl(
    goal: AgentRedTeamGoal,
    surface: AgentRedTeamSurface,
  ): AgentRedTeamTurn[];
}

export interface AgentRedTeamCarrierFeature {
  kind: AgentRedTeamCarrierFeatureKind;
  summary: string;
  sourceView: "raw" | "normalized" | "decoded" | "visible" | "hidden";
}

export interface AgentRedTeamAttempt {
  id: string;
  campaignId: string;
  target: string;
  vector: AgentRedTeamVector;
  surface: AgentRedTeamSurface;
  impact: AgentRedTeamImpact;
  techniqueId: AgentRedTeamTechniqueId;
  mutationChain: AgentRedTeamMutationId[];
  carrierId: string;
  carrierVersion: string;
  carrierLabel: string;
  variant: AgentRedTeamAttemptVariant;
  comparisonGroupId: string;
  controlAttemptId?: string;
  renderedPrompt: string;
  turns: AgentRedTeamTurn[];
  createdAt: string;
  status: CoverageStatus;
  primitiveStack: AgentRedTeamPrimitiveId[];
  ablationGroupId?: string;
  ablatedPrimitiveId?: AgentRedTeamPrimitiveId;
  expectedDetectorBlindSpot?: string;
  oracle: AgentRedTeamOracle;
  seed?: AgentRedTeamSeed;
  artifacts: AgentRedTeamArtifact[];
  carrierFeatures: AgentRedTeamCarrierFeature[];
  /** @deprecated Planned attempts do not contain outcome signals. */
  signals: AgentRedTeamSignal[];
}

export interface AgentRedTeamArtifact {
  id: string;
  type:
    | "prompt"
    | "response"
    | "request"
    | "tool-trace"
    | "screenshot"
    | "decoded-view"
    | "note";
  label: string;
  content: string;
  sha256: string;
}

export interface AgentRedTeamEvent {
  kind: AgentRedTeamEventKind;
  name?: string;
  target?: string;
  value?: number | string | boolean;
  details?: string;
  observedAt?: string;
}

export interface AgentRedTeamObservation {
  id: string;
  campaignId: string;
  attemptId: string;
  recordedAt: string;
  responseText: string;
  toolTrace?: string;
  protectedCanaryMatched?: boolean;
  testIntegrityError?: string;
  events: AgentRedTeamEvent[];
  latencyMs?: number;
  inputTokens?: number;
  outputTokens?: number;
  artifacts: AgentRedTeamArtifact[];
}

export interface AgentRedTeamSignal {
  kind: AgentRedTeamSignalKind;
  severity: "info" | "low" | "medium" | "high" | "critical";
  summary: string;
  evidence: string;
  sourceView: "raw" | "normalized" | "decoded" | "visible" | "hidden";
}

export interface AgentRedTeamEvaluation {
  id: string;
  campaignId: string;
  attemptId: string;
  controlAttemptId?: string;
  verdict: AgentRedTeamEvaluationVerdict;
  evidenceStrength: AgentRedTeamEvidenceStrength;
  confidence: number;
  reasoning: string;
  outcomeSignals: AgentRedTeamSignal[];
  evidenceArtifactIds: string[];
  limitations: string[];
  judgeProvenance: "deterministic" | "semantic" | "hybrid";
  createdAt: string;
}

export interface CoverageItem<T extends string> {
  id: T;
  status: CoverageStatus;
  rationale?: string;
}

export interface AgentRedTeamCoverageMatrix {
  vectors: CoverageItem<AgentRedTeamVector>[];
  impacts: CoverageItem<AgentRedTeamImpact>[];
  surfaces: CoverageItem<AgentRedTeamSurface>[];
  techniques: CoverageItem<AgentRedTeamTechniqueId>[];
}

export interface AgentRedTeamCampaign {
  id: string;
  target: string;
  seed: string;
  createdAt: string;
  attempts: AgentRedTeamAttempt[];
  coverage: AgentRedTeamCoverageMatrix;
}

export interface AgentRedTeamCampaignSummary {
  campaignId: string;
  coverage: AgentRedTeamCoverageMatrix;
  counts: Record<AgentRedTeamEvaluationVerdict, number>;
  evidenceGaps: string[];
}

import type {
  AgentRedTeamCoverageMatrix,
  AgentRedTeamImpact,
  AgentRedTeamSurface,
  AgentRedTeamTechniqueId,
  AgentRedTeamVector,
  CoverageItem,
  CoverageStatus,
} from "./types";

export const AGENT_RED_TEAM_VECTORS: AgentRedTeamVector[] = [
  "direct-prompt-injection",
  "indirect-prompt-injection",
  "rag-document-injection",
  "browser-dom-injection",
  "email-ticket-comment-injection",
  "tool-output-injection",
  "tool-description-schema-poisoning",
  "mcp-tool-registry-poisoning",
  "memory-poisoning",
  "delegation-task-poisoning",
  "cross-session-persistence",
  "cross-agent-privilege-escalation",
  "reasoning-plan-log-forgery",
  "encoding-unicode-stego-bypass",
  "multimodal-hidden-instruction",
  "resource-exhaustion-token-bomb",
];

export const AGENT_RED_TEAM_IMPACTS: AgentRedTeamImpact[] = [
  "system-developer-prompt-disclosure",
  "secret-token-disclosure",
  "private-user-data-disclosure",
  "cross-tenant-data-exfiltration",
  "unauthorized-tool-invocation",
  "unsafe-external-communication",
  "unauthorized-state-change",
  "policy-refusal-bypass",
  "tool-routing-hijack",
  "privilege-escalation",
  "memory-corruption",
  "denial-of-service-cost-amplification",
];

export const AGENT_RED_TEAM_SURFACES: AgentRedTeamSurface[] = [
  "chat-input",
  "http-api-body",
  "http-api-headers",
  "browser-page-content",
  "uploaded-file",
  "ocr-image-content",
  "rag-corpus",
  "email-inbox",
  "support-ticket",
  "comment-field",
  "tool-return-value",
  "tool-name-description-schema",
  "mcp-server-metadata",
  "long-term-memory",
  "task-queue-planner-notes",
  "logs-traces-scratchpads",
];

export const AGENT_RED_TEAM_TECHNIQUES: AgentRedTeamTechniqueId[] = [
  "refusal-suppression-inversion",
  "prefill-affirmation",
  "format-scaffold-hijack",
  "divider-mode-switch",
  "authority-system-spoof",
  "persona-inversion",
  "fictional-frame",
  "reasoning-channel-abuse",
  "encoding-obfuscation",
  "invisible-unicode-stego",
  "token-manipulation",
  "length-detail-amplifier",
  "tool-surface-indirect",
  "multi-turn-crescendo",
  "resource-exhaustion-dos",
  "system-prompt-extraction",
  "payload-splitting",
  "stacked-composition",
];

function items<T extends string>(
  ids: T[],
  status: CoverageStatus,
): CoverageItem<T>[] {
  return ids.map((id) => ({ id, status }));
}

export function createCoverageMatrix(
  status: CoverageStatus = "not-tested",
): AgentRedTeamCoverageMatrix {
  return {
    vectors: items(AGENT_RED_TEAM_VECTORS, status),
    impacts: items(AGENT_RED_TEAM_IMPACTS, status),
    surfaces: items(AGENT_RED_TEAM_SURFACES, status),
    techniques: items(AGENT_RED_TEAM_TECHNIQUES, status),
  };
}

function mark<T extends string>(
  collection: CoverageItem<T>[],
  ids: readonly T[],
  status: CoverageStatus,
  rationale?: string,
): CoverageItem<T>[] {
  const selected = new Set(ids);
  return collection.map((item) =>
    selected.has(item.id) ? { ...item, status, rationale } : item,
  );
}

export function updateCoverageMatrix(
  matrix: AgentRedTeamCoverageMatrix,
  update: {
    vectors?: AgentRedTeamVector[];
    impacts?: AgentRedTeamImpact[];
    surfaces?: AgentRedTeamSurface[];
    techniques?: AgentRedTeamTechniqueId[];
    status: CoverageStatus;
    rationale?: string;
  },
): AgentRedTeamCoverageMatrix {
  return {
    vectors: update.vectors
      ? mark(matrix.vectors, update.vectors, update.status, update.rationale)
      : matrix.vectors,
    impacts: update.impacts
      ? mark(matrix.impacts, update.impacts, update.status, update.rationale)
      : matrix.impacts,
    surfaces: update.surfaces
      ? mark(matrix.surfaces, update.surfaces, update.status, update.rationale)
      : matrix.surfaces,
    techniques: update.techniques
      ? mark(
          matrix.techniques,
          update.techniques,
          update.status,
          update.rationale,
        )
      : matrix.techniques,
  };
}

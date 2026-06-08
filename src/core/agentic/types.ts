// Core contracts for agentic (AI agent / LLM app) red-team scanning.
//
// A "case" is a single adversarial scenario delivered to a target agent through
// a TargetAdapter. The runner delivers it, observes the agent's reply (and any
// tool / connected-action / sub-agent activity surfaced in the transcript), and
// the oracle scores whether the attack succeeded. Detection leans on out-of-band
// canary callbacks so success is a fact (a token hit our collector) rather than
// an inference from transcript text — with a transcript-echo fallback for
// chat-only exfil (markdown image / link).

/** Vulnerability class under test. */
export type Category =
  | "direct-pi"
  | "indirect-pi"
  | "tool-abuse"
  | "exfil"
  | "markdown-exfil"
  | "agent-handoff";

/**
 * How the adversarial payload reaches the agent.
 *
 * - `chat` — typed straight into the conversation (direct injection)
 * - `knowledge` — lives in retrieved Knowledge (uploaded doc / connected source)
 * - `tool-output` — lives in the output of a tool the agent runs
 * - `connected-action` — steers an outbound action (HTTP request / email / CRM)
 * - `agent-handoff` — rides a task passed from one agent to a downstream agent
 * - `webpage` — lives in a page the agent scrapes / a web-search result
 */
export type Channel =
  | "chat"
  | "knowledge"
  | "tool-output"
  | "connected-action"
  | "agent-handoff"
  | "webpage";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** A minted canary the payload can call back to. */
export interface CanaryHandle {
  /** Opaque per-case token, also embedded in the callback path. */
  token: string;
  /** Full URL a payload should hit (e.g. https://host/c/<token>). */
  url: string;
}

/** Runtime context handed to a case when its prompt is built. */
export interface CaseContext {
  canary: CanaryHandle;
  /** Canary secret values planted into the conversation context (exfil cases). */
  plantedSecrets: Record<string, string>;
}

export interface SuccessCriteria {
  /** Exploited if the case's canary token was observed by the collector. */
  canaryCallback?: boolean;
  /** Exploited if the agent transcript matches this pattern. */
  transcriptMatches?: RegExp;
  /**
   * Exploited if the agent's reply echoes the canary token (URL) back to the
   * user — the signal for markdown-image / link exfil in rendering chat UIs.
   */
  transcriptContainsCanary?: boolean;
  /** Optional natural-language criterion for an agentic judge. */
  judgePrompt?: string;
}

export interface RedTeamCase {
  id: string;
  category: Category;
  channel: Channel;
  title: string;
  severity: Severity;
  /** What a successful exploit proves and why it matters. */
  impact: string;
  /** Trusted-context turns sent before the attack prompt (e.g. a planted secret). */
  seedMessages?: (ctx: CaseContext) => string[];
  /** Build the attack message delivered to the agent. */
  buildPrompt: (ctx: CaseContext) => string;
  /** Canary secrets to plant in the conversation context for this case. */
  secrets?: (ctx: CaseContext) => Record<string, string>;
  success: SuccessCriteria;
  /** Remediation guidance recorded on a resulting finding. */
  remediation?: string;
}

export type CaseStatus =
  | "exploited"
  | "defended"
  | "inconclusive"
  | "skipped"
  | "error";

export interface AgenticTranscript {
  sessionId: string;
  url?: string;
  status: string;
  messages: { role: string; text: string }[];
  structuredOutput?: unknown;
}

export interface JudgeVerdict {
  exploited: boolean;
  confidence: number;
  reasoning: string;
}

export interface CanaryHit {
  token: string;
  at: string;
  method: string;
  path: string;
  query: string;
  body: string;
}

export interface CaseResult {
  case: Pick<
    RedTeamCase,
    "id" | "category" | "channel" | "title" | "severity" | "impact"
  > & { remediation?: string };
  status: CaseStatus;
  canaryFired: boolean;
  canaryHits: CanaryHit[];
  signals: string[];
  judge?: JudgeVerdict;
  transcript?: AgenticTranscript;
  error?: string;
  startedAt: string;
  finishedAt: string;
}

export interface RunReport {
  startedAt: string;
  finishedAt: string;
  dryRun: boolean;
  total: number;
  byStatus: Record<CaseStatus, number>;
  results: CaseResult[];
}

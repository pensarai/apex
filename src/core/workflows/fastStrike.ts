import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ModelMessage, ToolSet } from "ai";
import { z } from "zod";
import {
  type Finding,
  OffensiveSecurityAgent,
  type PlaywrightMcpSession,
  type UnifiedSandbox,
} from "../agents/offSecAgent";
import { AgentEventBus } from "../eventBus";
import { FindingsRegistry } from "../findings/registry";
import {
  buildPentestReport,
  REPORT_FILENAME_JSON,
  REPORT_FILENAME_MD,
  renderJson,
  renderMarkdown,
} from "../report";
import { createThreatModelPrompt } from "../utils/prompt";
import { FastStrikeEvidenceLedger } from "./fastStrikeEvidence";
import type { PentestWorkflowInput, PentestWorkflowResult } from "./pentest";

export const FastStrikeStatus = z.enum([
  "impact-proven",
  "exhausted",
  "blocked",
]);

export const FastStrikeEvidenceReference = z.object({
  description: z.string().min(1),
  toolCallId: z.string().min(1),
  toolName: z.string().min(1),
});

export const FastStrikeResult = z.object({
  status: FastStrikeStatus.describe(
    "impact-proven only when material impact is demonstrated; exhausted after bounded credible paths are tested; blocked only for an external prerequisite",
  ),
  summary: z
    .string()
    .describe("The causal exploit path or honest stopping reason"),
  evidence: z
    .array(FastStrikeEvidenceReference)
    .optional()
    .describe("Trace-linked observations supporting the status"),
});

export type FastStrikeAgentOutcome = z.infer<typeof FastStrikeResult>;
export type FastStrikeEvidence = z.infer<typeof FastStrikeEvidenceReference>;

export interface FastStrikeFindingReference {
  title: string;
  endpoint: string;
  pocPath: string;
}

export interface FastStrikeObjectiveOutcome extends FastStrikeAgentOutcome {
  findings: FastStrikeFindingReference[];
}

const EXACT_FLAG_PATTERN = /FLAG\{(?!\.\.\.\})[^}\r\n]+\}/;
const DEFAULT_COMPETITIVE_LANE_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_RESPONSE_REJECTIONS = 4;

export function resolveFastStrikeLaneTimeoutMs(
  laneCount: number,
  configuredTimeoutMs?: number,
): number | undefined {
  if (configuredTimeoutMs !== undefined) return configuredTimeoutMs;
  return laneCount > 1 ? DEFAULT_COMPETITIVE_LANE_TIMEOUT_MS : undefined;
}

export function requestsExactFlag(guidance: string | undefined): boolean {
  if (!guidance) return false;
  return (
    /format\s*:\s*FLAG\{/i.test(guidance) ||
    /exact\s+FLAG\{/i.test(guidance) ||
    /exact\s+flag/i.test(guidance)
  );
}

function containsExactFlag(result: FastStrikeAgentOutcome): boolean {
  return EXACT_FLAG_PATTERN.test(
    [
      result.summary,
      ...(result.evidence ?? []).map(({ description }) => description),
    ].join("\n"),
  );
}

type EvidenceValidator = (
  evidence: FastStrikeEvidence[] | undefined,
) => string | undefined;

export function rejectUnverifiedFastStrikeResponse(
  result: unknown,
  options: {
    exactFlagRequired: boolean;
    rejectionCount: number;
    validateImpactEvidence?: EvidenceValidator;
  },
): { message: string } | undefined {
  const parsed = FastStrikeResult.safeParse(result);
  const evidenceRejection =
    parsed.success && parsed.data.status === "impact-proven"
      ? options.validateImpactEvidence?.(parsed.data.evidence)
      : undefined;

  if (
    parsed.success &&
    !evidenceRejection &&
    (parsed.data.status !== "impact-proven" ||
      !options.exactFlagRequired ||
      containsExactFlag(parsed.data))
  ) {
    return undefined;
  }
  if (options.rejectionCount >= MAX_RESPONSE_REJECTIONS) return undefined;
  if (evidenceRejection) {
    return {
      message: `${evidenceRejection} Cite the exact toolCallId and toolName of the successful observation, then respond again.`,
    };
  }
  return {
    message:
      parsed.success && parsed.data.status === "impact-proven"
        ? "Impact was claimed without the literal FLAG{...} requested by the objective. Inspect the successful observation and include the exact value."
        : "The response did not satisfy the objective contract. Continue from verified evidence and take one materially different bounded action before responding again.",
  };
}

export function normalizeFastStrikeOutcome(
  value: unknown,
  options: {
    exactFlagRequired?: boolean;
    validateImpactEvidence?: EvidenceValidator;
  } = {},
): FastStrikeAgentOutcome {
  const parsed = FastStrikeResult.safeParse(value);
  if (!parsed.success) {
    return {
      status: "blocked",
      summary: "The worker ended without a valid objective result.",
    };
  }

  const evidenceRejection =
    parsed.data.status === "impact-proven"
      ? options.validateImpactEvidence?.(parsed.data.evidence)
      : undefined;
  if (evidenceRejection) {
    return {
      status: "exhausted",
      summary: `Impact was claimed without valid trace-linked evidence: ${evidenceRejection} ${parsed.data.summary}`,
      evidence: parsed.data.evidence,
    };
  }
  if (
    parsed.data.status === "impact-proven" &&
    options.exactFlagRequired &&
    !containsExactFlag(parsed.data)
  ) {
    return {
      status: "exhausted",
      summary: `Impact was claimed without the required literal FLAG{...}: ${parsed.data.summary}`,
      evidence: parsed.data.evidence,
    };
  }
  return parsed.data;
}

type CompetitiveSettlement<T> =
  | { index: number; status: "fulfilled"; value: T }
  | { index: number; status: "rejected"; error: unknown };

export async function runCompetitiveLanes<T>(
  factories: Array<(signal: AbortSignal) => Promise<T>>,
  isSuccessful: (value: T) => boolean,
  parentSignal?: AbortSignal,
): Promise<T> {
  if (factories.length === 0) throw new Error("At least one lane is required");

  const controllers = factories.map(() => new AbortController());
  const pending = new Map(
    factories.map((factory, index) => {
      const controller = controllers[index];
      if (!controller) throw new Error(`Missing controller for lane ${index}`);
      const signal = parentSignal
        ? AbortSignal.any([parentSignal, controller.signal])
        : controller.signal;
      const settlement = factory(signal).then(
        (value): CompetitiveSettlement<T> => ({
          index,
          status: "fulfilled",
          value,
        }),
        (error): CompetitiveSettlement<T> => ({
          index,
          status: "rejected",
          error,
        }),
      );
      return [index, settlement] as const;
    }),
  );
  const completed: CompetitiveSettlement<T>[] = [];

  while (pending.size > 0) {
    const settlement = await Promise.race(pending.values());
    pending.delete(settlement.index);
    completed.push(settlement);
    if (settlement.status === "fulfilled" && isSuccessful(settlement.value)) {
      for (const [index] of pending) controllers[index]?.abort();
      await Promise.all(pending.values());
      return settlement.value;
    }
  }

  const completedValue = completed.find(
    (
      settlement,
    ): settlement is Extract<
      CompetitiveSettlement<T>,
      { status: "fulfilled" }
    > => settlement.status === "fulfilled",
  );
  if (completedValue) return completedValue.value;
  if (parentSignal?.aborted) {
    throw parentSignal.reason ?? new DOMException("Aborted", "AbortError");
  }
  throw new AggregateError(
    completed.flatMap((settlement) =>
      settlement.status === "rejected" ? [settlement.error] : [],
    ),
    "Every fast-strike lane failed",
  );
}

export const FAST_STRIKE_SYSTEM_PROMPT = `You are a focused offensive security operator executing one authorized impact objective.

Use a tight observe → hypothesize → act → prune → exploit → verify loop. Start with the strongest evidence-backed hypotheses, test them with discriminating requests, and retire disproven paths. When work becomes stateful, repetitive, protocol-heavy, or multi-stage, externalize it into an editable script in the session scratchpad and iterate there.

Once a primitive is confirmed, drive it end to end and pivot through related in-scope services when the objective requires it. Preserve viable primitives and concrete observations so another operator can continue the chain. Load relevant exploit-family guidance on demand; do not execute a generic vulnerability checklist.

Document a vulnerability only after proving an exploitable causal path and material impact. Return impact-proven only with trace-linked evidence from successful observation-producing tool calls. Return exhausted after bounded credible paths are tested without impact, or blocked only when an external prerequisite prevents safe in-scope progress. Stay within scope, preserve availability, and never perform destructive actions without explicit authorization.`;

export interface FastStrikeObjectiveInput
  extends Pick<
    PentestWorkflowInput,
    | "target"
    | "model"
    | "session"
    | "authConfig"
    | "abortSignal"
    | "eventBus"
    | "onStepFinish"
    | "enableThinking"
    | "thinkingEffort"
    | "openAIReasoningEffort"
    | "toolProtocol"
  > {
  objective: string;
  /** Existing lane conversation when resuming a durable worker. */
  messages?: ModelMessage[];
  findingsRegistry?: FindingsRegistry;
  laneCount?: number;
  laneTimeoutMs?: number;
  subagentPrefix?: string;
  singleLaneId?: string;
  sandbox?: UnifiedSandbox;
  browserSession?: PlaywrightMcpSession;
  environmentVariables?: Record<string, string>;
  secretValues?: string[];
  display?: string;
  extraTools?: ToolSet;
  directTools?: string[];
  engagementTargetIds?: readonly string[];
}

function findingReference(finding: Finding): FastStrikeFindingReference {
  return {
    title: finding.title,
    endpoint: finding.endpoint,
    pocPath: finding.pocPath,
  };
}

/** Execute one objective without owning discovery, coverage, or reporting. */
export async function runFastStrikeObjective(
  input: FastStrikeObjectiveInput,
): Promise<FastStrikeObjectiveOutcome> {
  const eventBus = input.eventBus ?? new AgentEventBus();
  const evidenceLedger = new FastStrikeEvidenceLedger(eventBus);
  try {
    return await executeFastStrikeObjective(
      { ...input, eventBus },
      evidenceLedger,
    );
  } finally {
    evidenceLedger.dispose();
  }
}

async function executeFastStrikeObjective(
  input: FastStrikeObjectiveInput & { eventBus: AgentEventBus },
  evidenceLedger: FastStrikeEvidenceLedger,
): Promise<FastStrikeObjectiveOutcome> {
  const laneCount = input.laneCount ?? 1;
  if (laneCount < 1 || laneCount > 3) {
    throw new Error("Fast Strike laneCount must be between 1 and 3");
  }
  if (input.browserSession && laneCount > 1) {
    throw new Error("A shared browser session requires one Fast Strike lane");
  }

  const findingsRegistry =
    input.findingsRegistry ??
    FindingsRegistry.fromDirectory(input.session.findingsPath, {
      model: input.model,
      authConfig: input.authConfig,
      abortSignal: input.abortSignal,
    });
  const findingsBefore = new Set(findingsRegistry.getFindings());
  const exactFlagRequired = requestsExactFlag(input.objective);
  const laneTimeoutMs = resolveFastStrikeLaneTimeoutMs(
    laneCount,
    input.laneTimeoutMs,
  );
  const prefix = input.subagentPrefix ?? "fast-strike";
  const laneIds = Array.from({ length: laneCount }, (_, index) =>
    laneCount === 1 && input.singleLaneId
      ? input.singleLaneId
      : `${prefix}-${index + 1}`,
  );

  const factories = laneIds.map((laneId) => async (laneSignal: AbortSignal) => {
    const timeoutSignal = laneTimeoutMs
      ? AbortSignal.timeout(laneTimeoutMs)
      : undefined;
    const abortSignal = timeoutSignal
      ? AbortSignal.any([laneSignal, timeoutSignal])
      : laneSignal;
    const validateImpactEvidence = (
      evidence: FastStrikeEvidence[] | undefined,
    ) => evidenceLedger.validateImpactEvidence(evidence, new Set([laneId]));
    const workspace = join(
      input.session.rootPath,
      "subagents",
      laneId,
      "workspace",
    );
    mkdirSync(workspace, { recursive: true });

    if (!input.singleLaneId) {
      input.eventBus.emit("subagent-spawn", {
        subagentId: laneId,
        name: `Fast Strike: ${input.objective.slice(0, 80)}`,
        input: { target: input.target, objective: input.objective },
      });
    }
    try {
      const agent = new OffensiveSecurityAgent<FastStrikeAgentOutcome>({
        system: FAST_STRIKE_SYSTEM_PROMPT,
        prompt: [
          `Target: ${input.target}`,
          `Assigned objective:\n${input.objective}`,
          `Correlation label: ${laneId}. Preserve state and evidence created under this label.`,
        ].join("\n\n"),
        model: input.model,
        session: input.session,
        target: input.target,
        mode: "fast-strike",
        toolProtocol: input.toolProtocol,
        extraTools: input.extraTools,
        directTools: input.directTools,
        engagementTargetIds: input.engagementTargetIds,
        activeTools: [],
        responseSchema: FastStrikeResult,
        responseGuard: (result, { rejectionCount }) =>
          rejectUnverifiedFastStrikeResponse(result, {
            exactFlagRequired,
            rejectionCount,
            validateImpactEvidence,
          }),
        findingsRegistry,
        messages: input.messages,
        subagentId: laneId,
        subagentName: `Fast Strike: ${input.objective.slice(0, 80)}`,
        agentCwd: workspace,
        authConfig: input.authConfig,
        abortSignal,
        eventBus: input.eventBus,
        onStepFinish: input.onStepFinish,
        enableThinking: input.enableThinking,
        thinkingEffort: input.thinkingEffort,
        openAIReasoningEffort: input.openAIReasoningEffort,
        sandbox: input.sandbox,
        browserSession: input.browserSession,
        environmentVariables: input.environmentVariables,
        secretValues: input.secretValues,
        display: input.display,
      });
      const outcome = normalizeFastStrikeOutcome(await agent.consume(), {
        exactFlagRequired,
        validateImpactEvidence,
      });
      if (!input.singleLaneId) {
        input.eventBus.emit("subagent-complete", {
          subagentId: laneId,
          status: "completed",
        });
      }
      return outcome;
    } catch (error) {
      if (!input.singleLaneId) {
        input.eventBus.emit("subagent-complete", {
          subagentId: laneId,
          status: "failed",
        });
      }
      if (timeoutSignal?.aborted && !laneSignal.aborted) {
        return {
          status: "exhausted" as const,
          summary: `The lane reached its bounded ${laneTimeoutMs}ms deadline without proving impact.`,
        };
      }
      throw error;
    }
  });

  let outcome: FastStrikeAgentOutcome;
  try {
    outcome = await runCompetitiveLanes(
      factories,
      (candidate) => candidate.status === "impact-proven",
      input.abortSignal,
    );
  } catch (error) {
    if (input.abortSignal?.aborted) throw error;
    outcome = {
      status: "blocked",
      summary: "Every Fast Strike lane failed before returning a valid result.",
    };
  }

  if (input.abortSignal?.aborted) {
    throw new DOMException("Pentest aborted by user", "AbortError");
  }
  const findings = findingsRegistry
    .getFindings()
    .filter((finding) => !findingsBefore.has(finding))
    .map(findingReference);
  return { ...outcome, findings };
}

function ensureSessionConfig(
  session: PentestWorkflowInput["session"],
): NonNullable<PentestWorkflowInput["session"]["config"]> {
  if (!session.config) {
    (session as { config: Record<string, unknown> }).config = {};
  }
  return session.config as NonNullable<
    PentestWorkflowInput["session"]["config"]
  >;
}

/** User-selected standalone Fast Strike workflow. */
export async function runFastStrike(
  input: PentestWorkflowInput,
): Promise<PentestWorkflowResult> {
  const { target, cwd, model, session, eventBus, prompt, threatModel } = input;
  if (cwd) ensureSessionConfig(session).codebasePath ??= cwd;
  if (prompt || threatModel) {
    const guidance = [
      threatModel ? createThreatModelPrompt(threatModel) : "",
      prompt ?? "",
    ]
      .filter(Boolean)
      .join("\n\n");
    const config = ensureSessionConfig(session);
    config.prompt = config.prompt
      ? `${config.prompt}\n\n${guidance}`
      : guidance;
  }

  const objective =
    session.config?.prompt ??
    "Find and chain exploitable vulnerabilities to demonstrate material security impact.";
  eventBus?.emit("workflow-phase-start", {
    phase: "pentesting",
    label: "Fast Strike",
    metadata: { target, objective },
  });
  const findingsRegistry = FindingsRegistry.fromDirectory(
    session.findingsPath,
    {
      model,
      authConfig: input.authConfig,
      abortSignal: input.abortSignal,
    },
  );
  const fastStrikeOutcome = await runFastStrikeObjective({
    ...input,
    objective,
    findingsRegistry,
    laneCount: session.config?.fastStrikeLanes ?? 1,
    laneTimeoutMs: session.config?.fastStrikeLaneTimeoutMs,
  });

  await findingsRegistry.groupByRootCause();
  const findings = [...findingsRegistry.getFindings()];
  const mode: "blackbox" | "whitebox" = cwd ? "whitebox" : "blackbox";
  const report = buildPentestReport(findings, {
    target,
    model,
    sessionId: session.id,
    mode,
  });
  const reportPath = join(session.rootPath, REPORT_FILENAME_MD);
  writeFileSync(reportPath, renderMarkdown(report));
  writeFileSync(
    join(session.rootPath, REPORT_FILENAME_JSON),
    renderJson(report),
  );
  eventBus?.emit("workflow-phase-complete", {
    phase: "pentesting",
    summary: {
      findingsCount: findings.length,
      objectiveStatus: fastStrikeOutcome.status,
      operatorSummary: fastStrikeOutcome.summary,
    },
  });
  return {
    findings,
    findingsPath: session.findingsPath,
    pocsPath: session.pocsPath,
    reportPath,
    fastStrikeOutcome,
  };
}

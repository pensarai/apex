import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { OffensiveSecurityAgent } from "../agents/offSecAgent";
import { FindingsRegistry } from "../findings/registry";
import {
  buildPentestReport,
  REPORT_FILENAME_JSON,
  REPORT_FILENAME_MD,
  renderJson,
  renderMarkdown,
} from "../report";
import { createThreatModelPrompt } from "../utils/prompt";
import type { PentestWorkflowInput, PentestWorkflowResult } from "./pentest";

const FastStrikeResult = z.object({
  solved: z
    .boolean()
    .describe(
      "True if the objective was achieved — a vulnerability was confirmed and, where applicable, the flag or sensitive data was extracted.",
    ),
  summary: z
    .string()
    .describe(
      "Concise account of the vulnerability exploited, the exact steps that worked, and any flag or sensitive data recovered.",
    ),
});

type FastStrikeOutcome = z.infer<typeof FastStrikeResult>;

export function normalizeFastStrikeOutcome(value: unknown): FastStrikeOutcome {
  const parsed = FastStrikeResult.safeParse(value);
  if (parsed.success) return parsed.data;
  return {
    solved: false,
    summary:
      "Lane ended without a valid accepted response; sibling lanes may continue.",
  };
}

type CompetitiveSettlement<T> =
  | { index: number; status: "fulfilled"; value: T }
  | { index: number; status: "rejected"; error: unknown };

/** Run independent bounded lanes and cancel siblings after the first success. */
export async function runCompetitiveLanes<T>(
  factories: Array<(signal: AbortSignal) => Promise<T>>,
  isSuccessful: (value: T) => boolean,
  parentSignal?: AbortSignal,
): Promise<T> {
  if (factories.length === 0) {
    throw new Error("At least one competitive lane is required");
  }

  const controllers = factories.map(() => new AbortController());
  const settlements = factories.map(async (factory, index) => {
    const controller = controllers[index];
    if (!controller) throw new Error(`Missing controller for lane ${index}`);
    const signal = parentSignal
      ? AbortSignal.any([parentSignal, controller.signal])
      : controller.signal;
    try {
      return {
        index,
        status: "fulfilled" as const,
        value: await factory(signal),
      };
    } catch (error) {
      return { index, status: "rejected" as const, error };
    }
  });

  const pending = new Map(
    settlements.map((settlement, index) => [index, settlement] as const),
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
    completed
      .filter(
        (
          settlement,
        ): settlement is Extract<
          CompetitiveSettlement<T>,
          { status: "rejected" }
        > => settlement.status === "rejected",
      )
      .map((settlement) => settlement.error),
    "Every fast-strike lane failed",
  );
}

const FAST_STRIKE_LANE_GUIDANCE = [
  `Operate as the primary evidence-first lane. Follow the strongest observed signal, minimize speculative breadth, and close the shortest verified path to impact. Before mutating shared or global state, capture a baseline, use correlation-labeled values, and restore only state you introduced. Foreign correlated artifacts prove the target is shared; they do not by themselves invalidate a reproducible exploit path.`,
  `Operate as an independent challenger lane. Do not assume the obvious first hypothesis is correct. Look for a materially different trust boundary, protocol representation, state transition, parser behavior, or authorization path supported by observable evidence. When an adapter maps input into a framework request, event, claims, or context object, test evidence-supported envelope collisions, override or merge fields, and alternate nesting before guessing credentials or routes. For that bounded representation family, compose the observed nouns with merge or override semantics, try camelCase and snake_case, and include single- and double-underscore reserved-key forms; do not close mass assignment after testing direct nesting alone. Prefer discriminating controls over payload variations, and never brute-force an unbounded space.`,
  `Operate as an independent systems lane. Reconstruct the target's data flow from inputs through transformations to privileged sinks. Prioritize cross-component mismatches, alternate encodings, and multi-step composition, while retiring any path whose required primitive is contradicted by evidence.`,
] as const;

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

const FAST_STRIKE_SYSTEM_PROMPT = `You are an elite offensive security operator running a fast strike against a single target. You work ALONE and finish the job yourself — there is no team to hand off to, no swarm to spawn, no plan to file. Your edge is discipline and observation, not volume.

Run this loop, tightly:

1. OBSERVE — Read every response for signal before you act. Note the stack, headers, cookies, tokens, form fields, error messages, redirects, disabled controls, ID patterns. State what you just learned in one line before the next move.
2. HYPOTHESIZE — From that signal and your deep knowledge of web/app vulnerability classes, name the single most likely vulnerability and why the evidence points to it. Rank leads by signal strength and go for the strongest first. A disabled form field, an ID in a URL or JWT, advertised demo creds, an exposed schema — these are tells; read them.
3. ACT — Test that one hypothesis with the minimum number of commands. Every tool call should exist to confirm or kill a specific hypothesis.
4. PRUNE — If the evidence disproves a lead, drop it and move to the next-strongest. Do NOT re-run a disproven approach or grind a dead end. Do NOT enumerate, brute-force, or run wordlists unless a specific signal demands it — choose techniques from evidence, not from a checklist.
5. EXPLOIT — When a vulnerability is confirmed, exploit it: capture the flag, extract the sensitive data, and pivot through it if the objective requires more. Multi-step objectives are yours to finish end to end — foothold, then privesc, then the goal.
6. DOCUMENT & FINISH — Record each confirmed vulnerability with the document_vulnerability tool as you go. When the objective is met (or every credible lead is exhausted), call the response tool with your result.

Rules:
- You are one operator. Plan in your head and in short text notes — never via planning tools, task lists, or sub-agents.
- Recon and exploitation are the same loop. Do just enough recon to form the first hypothesis, then start testing. Do not map the entire surface before acting.
- Bias toward the shortest path that proves impact. Speed comes from picking the right lead, not from skipping verification — always confirm a finding before you claim it.
- Stay in scope. Only touch the target you were given and hosts it legitimately depends on.`;

/** Single-operator pentest: skips attack-surface/swarm, returns {@link PentestWorkflowResult}. */
export async function runFastStrike(
  input: PentestWorkflowInput,
): Promise<PentestWorkflowResult> {
  const {
    target,
    cwd,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    onStepFinish,
    enableThinking,
    openAIReasoningEffort,
    toolProtocol,
    prompt,
    threatModel,
  } = input;

  if (cwd) {
    ensureSessionConfig(session).codebasePath ??= cwd;
  }

  // Merge prompt/threatModel into session.config.prompt, mirroring the full
  // workflow. The CLI passes operator guidance via session.config.prompt (not
  // input.prompt/threatModel), so this is the canonical source to read from.
  if (prompt || threatModel) {
    const parts: string[] = [];
    if (threatModel) parts.push(createThreatModelPrompt(threatModel));
    if (prompt) parts.push(prompt);
    const combined = parts.join("\n\n");

    const sessionConfig = ensureSessionConfig(session);
    sessionConfig.prompt = sessionConfig.prompt
      ? `${sessionConfig.prompt}\n\n${combined}`
      : combined;
  }

  const operatorGuidance = session.config?.prompt;

  const mode: "blackbox" | "whitebox" = cwd ? "whitebox" : "blackbox";

  eventBus?.emit("workflow-phase-start", {
    phase: "pentesting",
    label: "Fast Strike",
    metadata: { target },
  });

  const findingsRegistry = FindingsRegistry.fromDirectory(
    session.findingsPath,
    { model, authConfig, abortSignal },
  );

  const promptParts: string[] = [`Target: ${target}`];
  if (operatorGuidance) promptParts.push(operatorGuidance);
  promptParts.push(
    "Run the fast strike: find and exploit the vulnerability, complete the objective, and report what worked.",
  );

  const laneCount = session.config?.fastStrikeLanes ?? 2;
  const laneFactories = Array.from({ length: laneCount }, (_, laneIndex) => {
    const laneId = `fast-strike-${laneIndex + 1}`;
    const laneWorkspace = join(
      session.rootPath,
      "subagents",
      laneId,
      "workspace",
    );
    mkdirSync(laneWorkspace, { recursive: true });

    return async (laneSignal: AbortSignal) => {
      const agent = new OffensiveSecurityAgent<FastStrikeOutcome>({
        system: FAST_STRIKE_SYSTEM_PROMPT,
        prompt: [
          ...promptParts,
          `Use ${laneId} as a correlation label for accounts, messages, callbacks, and other state you create. Treat uncorrelated artifacts as unverified and do not pivot from them without reproducing the observation under your own label. The target may be shared with sibling lanes: never delete or overwrite foreign labeled state, and do not abandon a reproducible path merely because foreign artifacts exist.`,
          FAST_STRIKE_LANE_GUIDANCE[laneIndex] ??
            FAST_STRIKE_LANE_GUIDANCE[FAST_STRIKE_LANE_GUIDANCE.length - 1],
        ].join("\n\n"),
        model,
        session,
        target,
        mode: "fast-strike",
        toolProtocol,
        activeTools: [],
        responseSchema: FastStrikeResult,
        ...(session.config?.requireSuccessfulResponse
          ? {
              responseGuard: (result: unknown, { rejectionCount }) => {
                const parsed = FastStrikeResult.safeParse(result);
                if (parsed.success && parsed.data.solved) return undefined;
                // Two recovery opportunities are enough to redirect a
                // premature finish without turning completion into a loop.
                if (rejectionCount >= 2) return undefined;
                return {
                  message:
                    "The objective is still unsolved, so this run is not complete. " +
                    "Continue from verified evidence, retire failed paths, and take " +
                    "a materially different bounded action before responding again.",
                };
              },
            }
          : {}),
        findingsRegistry,
        subagentId: laneId,
        subagentName: `Fast Strike Lane ${laneIndex + 1}`,
        agentCwd: laneWorkspace,
        authConfig,
        abortSignal: laneSignal,
        eventBus,
        onStepFinish,
        enableThinking,
        openAIReasoningEffort,
      });
      return normalizeFastStrikeOutcome(await agent.consume());
    };
  });

  const strikeResult = await runCompetitiveLanes(
    laneFactories,
    (result) => result.solved,
    abortSignal,
  );

  if (abortSignal?.aborted) {
    throw new DOMException("Pentest aborted by user", "AbortError");
  }

  await findingsRegistry.groupByRootCause();
  const findings = [...findingsRegistry.getFindings()];

  const report = buildPentestReport(findings, {
    target,
    model,
    sessionId: session.id,
    mode,
  });
  const mdPath = join(session.rootPath, REPORT_FILENAME_MD);
  const jsonPath = join(session.rootPath, REPORT_FILENAME_JSON);
  writeFileSync(mdPath, renderMarkdown(report));
  writeFileSync(jsonPath, renderJson(report));

  eventBus?.emit("workflow-phase-complete", {
    phase: "pentesting",
    summary: {
      findingsCount: findings.length,
      ...(strikeResult
        ? { solved: strikeResult.solved, operatorSummary: strikeResult.summary }
        : {}),
    },
  });

  return {
    findings,
    findingsPath: session.findingsPath,
    pocsPath: session.pocsPath,
    reportPath: mdPath,
  };
}

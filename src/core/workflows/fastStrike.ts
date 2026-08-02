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

const EXACT_FLAG_PATTERN = /FLAG\{(?!\.\.\.\})[^}\r\n]+\}/;

export function requestsExactFlag(guidance: string | undefined): boolean {
  if (!guidance) return false;
  return (
    /format\s*:\s*FLAG\{/i.test(guidance) ||
    /exact\s+FLAG\{/i.test(guidance) ||
    /exact\s+flag/i.test(guidance)
  );
}

export function rejectUnverifiedFastStrikeResponse(
  result: unknown,
  options: { exactFlagRequired: boolean; rejectionCount: number },
): { message: string } | undefined {
  const parsed = FastStrikeResult.safeParse(result);
  if (
    parsed.success &&
    parsed.data.solved &&
    (!options.exactFlagRequired || EXACT_FLAG_PATTERN.test(parsed.data.summary))
  ) {
    return undefined;
  }
  // Two recovery opportunities redirect premature completion without turning
  // a genuinely exhausted run into an unbounded response loop.
  if (options.rejectionCount >= 2) return undefined;
  if (parsed.success && parsed.data.solved && options.exactFlagRequired) {
    return {
      message:
        "You marked the objective solved, but the summary does not contain the exact recovered FLAG{...} value. " +
        "Inspect the successful response or preserved UI state, extract the literal flag, and only then respond again.",
    };
  }
  return {
    message:
      "The objective is still unsolved, so this run is not complete. " +
      "Continue from verified evidence, retire failed paths, and take " +
      "a materially different bounded action before responding again.",
  };
}

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
  `Operate as the primary exploitation lane. Follow the strongest observed signal, but spend a small bounded discovery budget on adjacent routes, client assets, schemas, and the conventional variants of the vulnerability class named or implied by the objective. Once a primitive is confirmed, drive it through every explicit objective clause to the final proof. Before mutating shared or global state, capture a baseline, use correlation-labeled values, and restore only state you introduced. Foreign correlated artifacts prove the target is shared; they do not by themselves invalidate a reproducible exploit path.`,
  `Operate as an independent challenger lane. Do not assume the obvious first hypothesis is correct. Look for a materially different trust boundary, protocol representation, state transition, parser behavior, or authorization path supported by observable evidence. When an adapter maps input into a framework request, event, claims, or context object, test evidence-supported envelope collisions, override or merge fields, and alternate nesting before guessing credentials or routes. For that bounded representation family, compose the observed nouns with merge or override semantics, try camelCase and snake_case, and include single- and double-underscore reserved-key forms; do not close mass assignment after testing direct nesting alone. Prefer discriminating controls over payload variations, and never brute-force an unbounded space.`,
  `Operate as an independent systems lane. Reconstruct the target's data flow from inputs through transformations to privileged sinks. Prioritize cross-component mismatches, alternate encodings, protocol-native operations, and end-to-end multi-step composition. Use small automated matrices when the search space is finite and justified. Retire a path only when the required primitive—not merely one payload representation—is contradicted by evidence.`,
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

const FAST_STRIKE_SYSTEM_PROMPT = `You are an elite offensive security operator running a fast strike against a single authorized target. You work ALONE and finish the job yourself — there is no team to hand off to, no swarm to spawn, no plan to file. Your edge is disciplined breadth followed by decisive exploitation.

Run this loop, tightly:

0. DECOMPOSE — Turn the supplied objective into a private completion ledger: every required action, state transition, proof, and safety constraint. Objective verbs are requirements, not flavor text. A flag or secret observed before the required transition or exploit chain is a lead, not completion; finish and verify every explicit clause before reporting it.
1. OBSERVE — Read every response for signal before you act. Note the stack, headers, cookies, tokens, form fields, error messages, redirects, disabled controls, ID patterns, client code, schemas, and named technologies. Keep narration short so execution receives the budget.
2. HYPOTHESIZE — Rank a small set of plausible vulnerability classes by objective fit and observed signal. Challenge text that names a technology, control, or attack class is actionable context: exercise its canonical exploit workflow instead of waiting for a second hint.
3. ACT — Test the leading hypotheses with discriminating requests. Batch independent read-only checks and use scripts for finite matrices. Targeted adjacent-route discovery, protocol table reads, small context-derived credential sets, encoding variants, and bounded parameter or identifier enumeration are allowed when they test a concrete hypothesis. Respect rate and availability constraints.
4. PRUNE — Drop a lead when its required primitive is contradicted. One rejected payload, route spelling, nesting form, or address representation does not disprove the whole class. Before pruning, cover the conventional representations that follow from the observed stack. Do not repeat an identical negative test or expand into an unbounded scan.
5. EXPLOIT — Once a primitive is confirmed, stop polishing recon and drive it end to end. Pivot across components, derive the next request from returned data or client/source artifacts, and reproduce the complete path. Prefer a working exploit script over dozens of manual variations.
6. VERIFY, DOCUMENT & FINISH — Verify all items in the completion ledger, including the intended state transition or final read/inference request. Record confirmed vulnerabilities with document_vulnerability. Only then call response with the exact proof and the steps that produced it. If the literal flag appears in an intermediate response, do not quote it in narration or stop immediately; complete the remaining objective steps first and include it only in the final response.

Rules:
- You are one operator. Plan in your head and in short text notes — never via planning tools, task lists, or sub-agents.
- Recon and exploitation are the same loop. Do enough bounded discovery to avoid tunnel vision, then start testing; do not spend the run mapping the entire surface.
- Bias toward the shortest path that proves impact. Speed comes from picking the right lead, not from skipping verification — always confirm a finding before you claim it.
- This is an authorized, disposable security evaluation. Do not stop to request source, credentials, a mailbox, or evaluator help while finite in-scope experiments remain. Do not confuse "not directly reachable" with "unreachable through the confirmed application primitive."
- Preserve availability. Never perform denial-of-service, uncontrolled concurrency, or destructive actions outside explicit authorization; small bounded concurrency is acceptable only for a concrete race or protocol hypothesis.
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
          `Treat one-shot inventory, coupons, reset tokens, invitations, jobs, and other finite target state as scarce shared resources. Never spend the only resource on an ordinary baseline. Learn the request shape without submitting it (for example from scripts, interception, or DOM state), then make the first irreversible mutation the actual bounded exploit. If a sibling consumes finite state, inspect preserved responses and pursue only evidence-supported recovery or alternate paths.`,
          `Build a private objective ledger from the supplied task before acting. Do not declare success merely because a flag-shaped value surfaced: satisfy each named transition, chain step, proof action, and safety condition, then make the final proof-producing request and report the literal value.`,
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
                return rejectUnverifiedFastStrikeResponse(result, {
                  exactFlagRequired: requestsExactFlag(operatorGuidance),
                  rejectionCount,
                });
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

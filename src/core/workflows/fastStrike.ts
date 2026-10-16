import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import type { FindingPolicy } from "../agents/offSecAgent";
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
import {
  assertDepth,
  inMemoryRegistryProvider,
  inProcessSeams,
  withFindingPersistedHook,
} from "./seams";

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

const FastStrikeExternalResult = z.object({
  solved: z.boolean().describe("True if the supplied objective was met."),
  summary: z
    .string()
    .describe(
      "Concise account of security findings and the evidence observed.",
    ),
  reportedFindings: z
    .array(z.string())
    .describe(
      "One concise evidence-backed description per discovered vulnerability.",
    ),
  submissionJson: z
    .string()
    .describe(
      "The exact task-defined JSON submission as a string, or an empty string when no JSON submission was requested. Do not invent fields.",
    ),
});

type FastStrikeOutcome =
  | z.infer<typeof FastStrikeResult>
  | z.infer<typeof FastStrikeExternalResult>;

export function buildFastStrikeSystemPrompt(
  findingPolicy: FindingPolicy = "native",
): string {
  const external = findingPolicy === "external";
  const objectiveStep = external
    ? "5. FOLLOW THE OBJECTIVE — Determine whether the observed behavior establishes a security weakness. For a detection-only objective, stop once the requested evidence is sufficient; develop an exploit or pivot only when the objective requires it."
    : "5. EXPLOIT — When a vulnerability is confirmed, exploit it: capture the flag, extract the sensitive data, and pivot through it if the objective requires more. Preserve viable primitives and build on them. Prefer extending a working script into an end-to-end exploit over rebuilding the chain with repeated one-off tool calls or stopping at the next network or protocol boundary.";
  const finishStep = external
    ? "6. REPORT & FINISH — Include each credible finding and its supporting observations in the caller's requested output. If the caller requested a JSON submission, include the exact JSON text in the response tool's submissionJson field as well; otherwise use an empty string. The caller evaluates findings after the run. Once the objective is met or credible leads are exhausted, call the response tool with the correct solved value and a concise summary."
    : "6. DOCUMENT & FINISH — Record each confirmed vulnerability with the document_vulnerability tool as you go. Before concluding that every credible lead is exhausted, account for each viable primitive and pursue any concrete path that could still close the objective. After this check, whether the objective was met or every credible lead was genuinely exhausted, call the response tool with the correct solved value and a concise summary.";
  const evidenceRule = external
    ? "- Bias toward the shortest path that satisfies the assigned objective. Distinguish observed evidence from hypotheses, and avoid separate in-run finding review."
    : "- Bias toward the shortest path that proves impact. Speed comes from picking the right lead, not from skipping verification — always confirm a finding before you claim it.";

  return `You are an elite offensive security operator running a fast strike against a single target. You work ALONE and finish the job yourself — there is no team to hand off to, no swarm to spawn, no plan to file. Your edge is discipline and observation, not volume.

Run this loop, tightly:

1. OBSERVE — Read every response for signal before you act. Note the stack, headers, cookies, tokens, form fields, error messages, redirects, disabled controls, ID patterns. State what you just learned in one line before the next move.
2. HYPOTHESIZE — From that signal and your deep knowledge of web/app vulnerability classes, name the single most likely vulnerability and why the evidence points to it. Rank leads by signal strength and go for the strongest first. A disabled form field, an ID in a URL or JWT, advertised demo creds, an exposed schema — these are tells; read them.
3. ACT — Test that one hypothesis with the strongest available technique. Use direct tools for quick probes, but treat the shell as a working environment rather than merely a way to issue one-off commands. When the work becomes stateful, repetitive, concurrent, protocol-heavy, or multi-stage, externalize it into an editable script in the session scratchpad directory identified in the workspace instructions. Never create a scratchpad/ directory inside the target repository. Run the script, inspect the results, modify it, and rerun it as the attack develops. For blind/out-of-band testing (SSRF, blind RCE, XSS callbacks), start_callback_listener gives you a nonce-correlated listener that survives intervening commands: embed the returned callback URL (only an address you know the target can reach — never a guessed one) in the payload, then poll_callback_listener for hits. Listener readiness and the tool's own self-test never count as target evidence; stop_callback_listener when done.
4. PRUNE — If the evidence disproves a lead, drop it and move to the next-strongest. Do NOT re-run a disproven approach or grind a dead end. Do NOT enumerate, brute-force, or run wordlists unless a specific signal demands it — choose techniques from evidence, not from a checklist.
${objectiveStep}
${finishStep}

Rules:
- You are one operator. Plan in your head and in short text notes — never via planning tools, task lists, or sub-agents.
- Recon and exploitation are the same loop. Do just enough recon to form the first hypothesis, then start testing. Do not map the entire surface before acting.
- Spend your reasoning on choosing techniques and interpreting evidence; use scripts for deterministic mechanics, iteration, and chain execution.
${evidenceRule}
- Stay in scope. Only touch the target you were given and hosts it legitimately depends on.`;
}

export const FAST_STRIKE_SYSTEM_PROMPT = buildFastStrikeSystemPrompt();

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
    onCacheMetrics,
    enableThinking,
    thinkingEffort,
    openAIReasoningEffort,
    prompt,
    threatModel,
    seams: inputSeams,
  } = input;

  // Default registries mirror today's `FindingsRegistry.fromDirectory` resume
  // behavior (dedup against on-disk findings, model-backed semantic dedup).
  const seams =
    inputSeams ??
    inProcessSeams({
      registries: {
        findings: () =>
          FindingsRegistry.fromDirectory(session.findingsPath, {
            model,
            authConfig,
            abortSignal,
            sessionId: session.id,
          }),
        attackSurface: inMemoryRegistryProvider.attackSurface,
      },
    });
  assertDepth(1, seams.limits);

  if (cwd) {
    if (!session.config) {
      (session as { config: Record<string, unknown> }).config = {};
    }
    session.config!.codebasePath ??= cwd;
  }

  // Merge prompt/threatModel into session.config.prompt, mirroring the full
  // workflow. The CLI passes operator guidance via session.config.prompt (not
  // input.prompt/threatModel), so this is the canonical source to read from.
  if (prompt || threatModel) {
    const parts: string[] = [];
    if (threatModel) parts.push(createThreatModelPrompt(threatModel));
    if (prompt) parts.push(prompt);
    const combined = parts.join("\n\n");

    if (!session.config) {
      (session as { config: Record<string, unknown> }).config = {};
    }
    session.config!.prompt = session.config?.prompt
      ? `${session.config?.prompt}\n\n${combined}`
      : combined;
  }

  const operatorGuidance = session.config?.prompt;
  const findingPolicy = input.hooks?.findingPolicy ?? input.findingPolicy;

  const mode: "blackbox" | "whitebox" = cwd ? "whitebox" : "blackbox";

  eventBus?.emit("workflow-phase-start", {
    phase: "pentesting",
    label: "Fast Strike",
    metadata: { target },
  });

  // Ops-typed by the seam; OffensiveSecurityAgent only calls the
  // FindingsRegistryOps surface, so this cast is safe for any
  // RegistryProvider implementation.
  const findingsRegistry = withFindingPersistedHook(
    seams.registries.findings(),
    seams.hooks.onFindingPersisted,
  ) as FindingsRegistry;

  const promptParts: string[] = [`Target: ${target}`];
  if (operatorGuidance) promptParts.push(operatorGuidance);
  promptParts.push(
    findingPolicy === "external"
      ? "Run the fast strike: investigate the target, identify security weaknesses, and submit the findings in the requested output. Stop when the supplied objective is met."
      : "Run the fast strike: find and exploit the vulnerability, complete the objective, and report what worked.",
  );

  const agent = new OffensiveSecurityAgent<FastStrikeOutcome>({
    subagentSpawner: input.subagentSpawner,
    languageModelMiddleware: input.languageModelMiddleware,
    usageRecorder: input.usageRecorder,
    streamIdFactory: input.streamIdFactory,
    ...input.hooks,
    system: buildFastStrikeSystemPrompt(findingPolicy),
    prompt: promptParts.join("\n\n"),
    model,
    session,
    target,
    mode: "fast-strike",
    findingPolicy,
    activeTools: [],
    responseSchema:
      findingPolicy === "external"
        ? FastStrikeExternalResult
        : FastStrikeResult,
    findingsRegistry,
    subagentId: "fast-strike",
    authConfig,
    abortSignal:
      abortSignal && input.hooks?.abortSignal
        ? AbortSignal.any([abortSignal, input.hooks.abortSignal])
        : (abortSignal ?? input.hooks?.abortSignal),
    eventBus,
    onStepFinish,
    onCacheMetrics,
    enableThinking,
    thinkingEffort,
    openAIReasoningEffort,
  });

  eventBus?.emit("subagent-spawn", {
    subagentId: "fast-strike",
    name: "Fast Strike",
    input: { target },
  });

  await seams.hooks.onEndpointStart?.({
    subagentId: "fast-strike",
    subagentName: "Fast Strike",
    target,
  });

  let completed:
    | { policy: "native"; outcome: FastStrikeOutcome }
    | {
        policy: "external";
        outcome: z.infer<typeof FastStrikeExternalResult>;
      };
  try {
    const strikeResult = await agent.consume();
    if (findingPolicy === "external") {
      const parsed = FastStrikeExternalResult.safeParse(strikeResult);
      if (!parsed.success) {
        throw new Error(
          "Externally graded Fast Strike ended without a structured findings response",
        );
      }
      completed = { policy: "external", outcome: parsed.data };
    } else {
      completed = { policy: "native", outcome: strikeResult };
    }
    eventBus?.emit("subagent-complete", {
      subagentId: "fast-strike",
      status: "completed",
    });
    await seams.hooks.onEndpointDone?.(
      { subagentId: "fast-strike", subagentName: "Fast Strike", target },
      completed.outcome,
    );
  } catch (e) {
    eventBus?.emit("subagent-complete", {
      subagentId: "fast-strike",
      status: "failed",
    });
    await seams.hooks.onEndpointFailed?.(
      { subagentId: "fast-strike", subagentName: "Fast Strike", target },
      e,
    );
    throw e;
  }

  if (abortSignal?.aborted) {
    throw new DOMException("Pentest aborted by user", "AbortError");
  }

  if (completed.policy === "external") {
    const strikeResult = completed.outcome;
    eventBus?.emit("workflow-phase-complete", {
      phase: "pentesting",
      summary: {
        findingsCount: strikeResult.reportedFindings.length,
        solved: strikeResult.solved,
        operatorSummary: strikeResult.summary,
      },
    });
    return {
      findings: [],
      findingsPath: session.findingsPath,
      pocsPath: session.pocsPath,
      reportPath: null,
      reportedFindings: strikeResult.reportedFindings,
      submissionJson: strikeResult.submissionJson,
    };
  }

  await findingsRegistry.groupByRootCause();
  const findings = [...findingsRegistry.getFindings()];
  const strikeResult = completed.outcome;

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

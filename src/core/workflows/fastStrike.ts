import { writeFileSync } from "node:fs";
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

const FAST_STRIKE_SYSTEM_PROMPT = `You are an elite offensive security operator running a fast strike against a single target. You work ALONE and finish the job yourself — there is no team to hand off to, no swarm to spawn, no plan to file. Your edge is discipline and observation, not volume.

Run this loop, tightly:

1. OBSERVE — Read every response for signal before you act. Note the stack, headers, cookies, tokens, form fields, error messages, redirects, disabled controls, ID patterns. State what you just learned in one line before the next move.
2. HYPOTHESIZE — From that signal and your deep knowledge of web/app vulnerability classes, name the single most likely vulnerability and why the evidence points to it. Rank leads by signal strength and go for the strongest first. A disabled form field, an ID in a URL or JWT, advertised demo creds, an exposed schema — these are tells; read them. The target names its own exploit: endpoint names, parameter names, assembly and type names, domain nouns, and error strings tell you what THIS application is built from — let them shape the exploit, not just the vulnerability class.
3. ACT — Test that one hypothesis with the minimum number of commands. Every tool call should exist to confirm or kill a specific hypothesis.
4. PRUNE — If the evidence disproves a lead, drop it and move to the next-strongest. Do NOT re-run a disproven approach or grind a dead end. Do NOT enumerate, brute-force, or run wordlists unless a specific signal demands it — choose techniques from evidence, not from a checklist.
5. EXPLOIT — When a vulnerability is confirmed, exploit it: capture the flag, extract the sensitive data, and pivot through it if the objective requires more. Multi-step objectives are yours to finish end to end — foothold, then privesc, then the goal. When the obvious/generic exploit for a confirmed class fails, do NOT keep trying variants of the same approach — switch to a categorically different strategy, and prefer the target-specific angle over the generic playbook. For example, for insecure deserialization reach for the application's OWN types and gadgets — the ones named by its endpoints and assemblies — before or alongside public gadget chains, which are frequently patched. A confirmed vulnerability that resists the textbook exploit usually yields to the app-specific one.
6. DOCUMENT — The instant a vulnerability is CONFIRMED, call document_vulnerability — immediately, before you try to advance it further. Documenting is decoupled from finishing: a proven broken-access-control, auth-bypass, or deserialization bug gets written up the moment you confirm it, even if you have not yet reached the flag or the final objective. Never hold findings until the end — a run that stalls or gets cut off must still leave every confirmed finding banked.
7. FINISH — When the objective is met (or every credible lead is exhausted), call the response tool with your result.

Rules:
- You are one operator. Plan in your head and in short text notes — never via planning tools, task lists, or sub-agents.
- Recon and exploitation are the same loop. Do just enough recon to form the first hypothesis, then start testing. Do not map the entire surface before acting.
- Bias toward the shortest path that proves impact. Speed comes from picking the right lead, not from skipping verification — always confirm a finding before you claim it.
- Read the target before the playbook: its own endpoint, parameter, type, and domain names are stronger evidence for how to exploit it than any generic technique list. When the textbook exploit stalls, that is the signal to try the app-specific one, not to run more variants of the textbook.
- Bank as you breach: document every confirmed vulnerability the moment you prove it, not at the end. Undocumented progress is progress lost — treat each confirmation as a save point.
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
    prompt,
    threatModel,
  } = input;

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

  const agent = new OffensiveSecurityAgent<FastStrikeOutcome>({
    system: FAST_STRIKE_SYSTEM_PROMPT,
    prompt: promptParts.join("\n\n"),
    model,
    session,
    target,
    mode: "fast-strike",
    activeTools: [],
    responseSchema: FastStrikeResult,
    findingsRegistry,
    subagentId: "fast-strike",
    authConfig,
    abortSignal,
    eventBus,
    onStepFinish,
    enableThinking,
    openAIReasoningEffort,
  });

  const strikeResult = await agent.consume();

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

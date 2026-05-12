import { hasToolCall, stepCountIs } from "ai";
import type { AIAuthConfig, AIModel } from "../../../ai";
import type { AgentEventBus } from "../../../eventBus";
import type { SessionInfo } from "../../../session";
import { OffensiveSecurityAgent } from "../../offSecAgent";
import {
  type BountyReport,
  type LiveVerificationResult,
  LiveVerificationResultSchema,
} from "./types";

const VERIFY_SYSTEM = `You are a bug bounty triage agent attempting to reproduce a reported vulnerability against a live target.

You have ONLY two action tools: http_request and execute_command. You may not read source code, document findings, or take any other action. When your investigation is complete, call the response tool with a structured verdict.

Rules:
- Attempt the PoC exactly as the reporter described it first. Vary only when the literal steps fail (e.g. different URL casing, missing query string).
- If the first attempt fails, try at most 3 reasonable variations before concluding non-reproducible.
- All HTTP must hit the configured target host — out-of-scope hosts are blocked at the tool level and will throw.
- Set reproduced=true ONLY if you have concrete HTTP-level evidence that the claimed vulnerability is present (e.g. the reflected payload appears in the response, the IDOR returns another user's data, the SSRF reaches an internal-only endpoint).
- Set reproduced=false if you cannot reproduce after reasonable variation. Include in observations what you tried and the responses you saw.
- The "evidence" field must contain concrete artifacts — status codes, headers, response body snippets, error messages. No hand-waving.
- Do NOT speculate about a fix. Triage only.`;

function buildVerifyPrompt(opts: {
  report: BountyReport;
  target: string;
}): string {
  const { report, target } = opts;
  const steps = report.pocSteps
    .map((s, i) => `${i + 1}. ${s}`)
    .join("\n");

  const curlSection = report.pocCurl
    ? `\n\n## Raw PoC request\n\`\`\`\n${report.pocCurl}\n\`\`\``
    : "";

  return `# Inbound Bug Bounty Report — Reproduction Attempt

Target: ${target}

## Reporter's claim
- Title: ${report.title}
- Vulnerability class: ${report.vulnerabilityClass}
- Affected URL: ${report.affectedUrl}
- Claimed severity: ${report.claimedSeverity}
- Attacker model: ${report.attackerModel}

## Description
${report.description}

## Claimed impact
${report.impact}

## PoC steps (from reporter)
${steps}${curlSection}

## Your task
Reproduce the issue against the live target using http_request and execute_command. When done, call the response tool with your structured verdict.`;
}

/**
 * Attempt to reproduce the reported vulnerability against the live target.
 *
 * Spawns an {@link OffensiveSecurityAgent} sub-run constrained to:
 *   - `http_request` — for HTTP-level reproduction
 *   - `execute_command` — for curl, openssl, etc. when needed
 *   - `response` — for the structured verdict
 *
 * All outbound traffic is scope-gated by the existing scopeGuard against
 * `session.config.scopeConstraints.allowedHosts`. The caller is responsible
 * for setting those constraints to permit only the configured target host.
 */
export async function runLiveVerification(opts: {
  report: BountyReport;
  target: string;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  eventBus?: AgentEventBus;
  abortSignal?: AbortSignal;
}): Promise<LiveVerificationResult> {
  const agent = new OffensiveSecurityAgent<LiveVerificationResult>({
    system: VERIFY_SYSTEM,
    prompt: buildVerifyPrompt({ report: opts.report, target: opts.target }),
    model: opts.model,
    session: opts.session,
    target: opts.target,
    activeTools: ["http_request", "execute_command", "response"],
    responseSchema: LiveVerificationResultSchema,
    authConfig: opts.authConfig,
    eventBus: opts.eventBus,
    abortSignal: opts.abortSignal,
    // Cap the verification at 30 steps — most live PoCs reproduce in 2-5
    // HTTP calls. Anything beyond 30 means the agent is wandering.
    stopWhen: [stepCountIs(30), hasToolCall("response")],
  });

  return agent.consume();
}

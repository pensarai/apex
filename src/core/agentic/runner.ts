import type { TargetAdapter } from "./adapters";
import type { CanaryProvider } from "./canary";
import { type AgenticJudge, scoreCase } from "./oracle";
import type { CaseContext, CaseResult, RedTeamCase } from "./types";

export interface RunCaseOptions {
  /** Grace period after a turn settles to let a late callback land (ms). */
  canaryGraceMs?: number;
  /** Optional agentic judge for ambiguous, no-callback cases. */
  judge?: AgenticJudge;
}

/**
 * Run one adversarial case against a target via the adapter, then score it.
 * Deterministic: success is decided by the canary oracle, not by the model.
 */
export async function runCase(
  c: RedTeamCase,
  adapter: TargetAdapter,
  canary: CanaryProvider,
  opts: RunCaseOptions = {},
): Promise<CaseResult> {
  const startedAt = new Date().toISOString();
  const handle = canary.mint();
  const ctx: CaseContext = { canary: handle, plantedSecrets: {} };
  ctx.plantedSecrets = c.secrets?.(ctx) ?? {};

  const base: CaseResult["case"] = {
    id: c.id,
    category: c.category,
    channel: c.channel,
    title: c.title,
    severity: c.severity,
    impact: c.impact,
    ...(c.remediation ? { remediation: c.remediation } : {}),
  };

  try {
    const prompt = c.buildPrompt(ctx);
    const seedMessages = c.seedMessages?.(ctx);
    const { sessionId } = await adapter.createSession({
      prompt,
      ...(seedMessages ? { seedMessages } : {}),
      caseId: c.id,
    });
    const transcript = await adapter.pollUntilTerminal(sessionId);

    if ((opts.canaryGraceMs ?? 0) > 0 && c.success.canaryCallback) {
      await new Promise((r) => setTimeout(r, opts.canaryGraceMs));
    }

    const scored = await scoreCase(
      c,
      transcript,
      canary,
      handle.token,
      opts.judge,
    );
    const status = scored.status;
    const signals = [...scored.signals];

    return {
      case: base,
      status,
      canaryFired: signals.includes("canary-callback"),
      canaryHits: canary.hits(handle.token),
      signals,
      judge: scored.judge,
      transcript,
      startedAt,
      finishedAt: new Date().toISOString(),
    };
  } catch (err) {
    return {
      case: base,
      status: "error",
      canaryFired: false,
      canaryHits: canary.hits(handle.token),
      signals: [],
      error: err instanceof Error ? err.message : String(err),
      startedAt,
      finishedAt: new Date().toISOString(),
    };
  }
}

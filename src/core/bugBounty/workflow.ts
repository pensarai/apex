import type { Finding } from "../agents/offSecAgent";
import type { AIAuthConfig, AIModel } from "../ai";
import type { AgentEventBus } from "../eventBus";
import { type SessionInfo, sessions } from "../session";
import { runPentestWorkflow } from "../workflows/pentest";
import type { EngagementPolicy } from "./types";

export interface BugBountyWorkflowInput {
  policy: EngagementPolicy;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  maxTargets?: number;
}

export interface BugBountyTargetResult {
  target: string;
  sessionId?: string;
  reportPath?: string | null;
  findings: Finding[];
  status: "completed" | "skipped" | "failed";
  reason?: string;
}

export interface BugBountyWorkflowResult {
  policyHash: string;
  findings: Finding[];
  targets: BugBountyTargetResult[];
  skippedTargets: string[];
}

export async function runBugBountyWorkflow(
  input: BugBountyWorkflowInput,
): Promise<BugBountyWorkflowResult> {
  if (!input.policy.canExecute) {
    throw new Error(
      `Bug bounty preflight is blocked: ${input.policy.blockers.join("; ")}`,
    );
  }

  const maxTargets = input.maxTargets ?? 25;
  const actionable = input.policy.allowedTargets
    .map((asset) => ({
      asset,
      target: toPentestTarget(asset.value, asset.type),
    }))
    .filter(
      (entry): entry is { asset: typeof entry.asset; target: string } =>
        entry.target !== null,
    );
  const selected = actionable.slice(0, maxTargets);
  const skippedTargets = [
    ...input.policy.allowedTargets
      .filter(
        (asset) =>
          !actionable.some((entry) => entry.asset.value === asset.value),
      )
      .map((asset) => asset.value),
    ...actionable.slice(maxTargets).map((entry) => entry.asset.value),
  ];
  const targetResults: BugBountyTargetResult[] = [];

  for (const { target } of selected) {
    if (input.abortSignal?.aborted) {
      throw new DOMException("Bug bounty run aborted", "AbortError");
    }
    const child = await sessions.create({
      name: `${input.policy.programName}: ${new URL(target).hostname}`,
      targets: [target],
      model: input.model,
      authConfig: input.authConfig,
      config: {
        ...input.session.config,
        mode: "auto",
        allowDestructiveActions: false,
        requestsPerSecond: input.policy.requestsPerSecond
          ? Math.min(
              input.session.config?.requestsPerSecond ??
                input.policy.requestsPerSecond,
              input.policy.requestsPerSecond,
            )
          : input.session.config?.requestsPerSecond,
        headers: {
          ...(input.session.config?.headers ?? {}),
          ...input.policy.requiredHeaders,
        },
        scopeConstraints: {
          ...input.session.config?.scopeConstraints,
          allowedHosts: input.policy.allowedHosts,
          strictScope: true,
        },
        engagementPolicy: input.policy,
        prompt: [input.session.config?.prompt, input.policy.guidance]
          .filter(Boolean)
          .join("\n\n"),
      },
    });

    try {
      const result = await runPentestWorkflow({
        target,
        model: input.model,
        session: child,
        authConfig: input.authConfig,
        abortSignal: input.abortSignal,
        eventBus: input.eventBus,
        prompt: input.policy.guidance,
      });
      targetResults.push({
        target,
        sessionId: child.id,
        reportPath: result.reportPath,
        findings: result.findings,
        status: "completed",
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") throw error;
      targetResults.push({
        target,
        sessionId: child.id,
        findings: [],
        status: "failed",
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return {
    policyHash: input.policy.policyHash,
    findings: targetResults.flatMap((result) => result.findings),
    targets: targetResults,
    skippedTargets,
  };
}

function toPentestTarget(value: string, type: string): string | null {
  if (type === "url") return value;
  if (type === "domain" || type === "ip") return `https://${value}`;
  return null;
}

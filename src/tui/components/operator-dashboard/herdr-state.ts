import type { HerdrReport, HerdrState } from "../../../core/integrations/herdr";
import type { DashboardStatus } from "./logic";

// Herdr reruns this argv after a server restart, so it must reproduce the
// session exactly — model and redaction included — and start with a bare
// command name on PATH.
function buildResumeArgv(
  sessionId: string | null,
  modelId: string | null,
  obfuscateEnabled: boolean,
): string[] {
  if (!sessionId) {
    return ["pensar", ...(obfuscateEnabled ? ["--obfuscate"] : [])];
  }
  return [
    "pensar",
    "--resume",
    sessionId,
    ...(modelId ? ["--model", modelId] : []),
    ...(obfuscateEnabled ? ["--obfuscate"] : []),
  ];
}

export interface HerdrDashboardSnapshot {
  status: DashboardStatus;
  loading: boolean;
  pendingApprovalCount: number;
  hasPendingQuestions: boolean;
  planReviewPending: boolean;
  sessionId: string | null;
  modelId: string | null;
  obfuscateEnabled: boolean;
}

function resolveHerdrState(input: HerdrDashboardSnapshot): {
  state: HerdrState;
  message?: string;
} {
  if (input.pendingApprovalCount > 0) {
    return {
      state: "blocked",
      message:
        input.pendingApprovalCount > 1
          ? `Waiting for tool approval (${input.pendingApprovalCount} queued)`
          : "Waiting for tool approval",
    };
  }
  if (input.hasPendingQuestions) {
    return { state: "blocked", message: "Waiting for answers" };
  }
  if (input.planReviewPending) {
    return { state: "blocked", message: "Waiting for plan review" };
  }
  if (input.loading || input.status === "running") {
    return { state: "working" };
  }
  return { state: "idle" };
}

export function buildHerdrSnapshot(input: HerdrDashboardSnapshot): HerdrReport {
  return {
    ...resolveHerdrState(input),
    session: {
      ...(input.sessionId ? { id: input.sessionId } : {}),
      resumeArgv: buildResumeArgv(
        input.sessionId,
        input.modelId,
        input.obfuscateEnabled,
      ),
    },
  };
}

// Home must not resurrect the session the user just left, so the resume argv
// resets to a bare launch. The process still owns the pane — never release.
export function buildHomeHerdrReport(obfuscateEnabled: boolean): HerdrReport {
  return {
    state: "idle",
    session: { resumeArgv: buildResumeArgv(null, null, obfuscateEnabled) },
  };
}

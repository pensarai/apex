import type { DisplayMessage, WorkflowData } from "../agent-display";
import { isToolMessage } from "../shared/type-guards";

// ---------------------------------------------------------------------------
// Pentest workflow projections — pure, immutable WorkflowData transitions.
// ---------------------------------------------------------------------------

/** Only pentest swarm agents (pentest-agent-*) appear in WorkflowData. */
export function isPentestAgent(id?: string): boolean {
  return id !== undefined && /^pentest-agent-\d+$/.test(id);
}

/** Default WorkflowData for a fresh run_pentest_workflow tool message. */
export function initialWorkflowData(): WorkflowData {
  return {
    currentPhase: "discovery",
    discovery: { label: "", status: "pending", logs: [] },
    pentesting: { label: "", status: "idle", subagents: {} },
    reporting: { label: "", status: "idle" },
  };
}

/** Patch the workflowData on the active run_pentest_workflow tool message. */
export function updateWorkflowDataMessage(
  messages: readonly DisplayMessage[],
  updater: (wd: WorkflowData) => WorkflowData,
): DisplayMessage[] {
  const idx = messages.findLastIndex(
    (m) =>
      isToolMessage(m) &&
      m.toolName === "run_pentest_workflow" &&
      (m.status === "pending" || m.status === "streaming"),
  );
  if (idx === -1) return messages as DisplayMessage[];
  const msg = messages[idx];
  const wd = msg.workflowData ?? initialWorkflowData();
  const updated = [...messages];
  updated[idx] = { ...msg, workflowData: updater(wd) };
  return updated;
}

/** Register a pentest swarm agent in the workflow's subagent map. */
export function applyWorkflowSubagentSpawn(
  wd: WorkflowData,
  subagentId: string,
  name?: string,
): WorkflowData {
  return {
    ...wd,
    pentesting: {
      ...wd.pentesting,
      subagents: {
        ...wd.pentesting.subagents,
        [subagentId]: { name, status: "pending", logs: [] },
      },
    },
  };
}

/** Record a pentest swarm agent's terminal status. */
export function applyWorkflowSubagentComplete(
  wd: WorkflowData,
  subagentId: string,
  status: "completed" | "failed",
): WorkflowData {
  const entry = wd.pentesting.subagents[subagentId];
  if (!entry) return wd;
  return {
    ...wd,
    pentesting: {
      ...wd.pentesting,
      subagents: {
        ...wd.pentesting.subagents,
        [subagentId]: { ...entry, status },
      },
    },
  };
}

/** Mark a workflow phase in-flight and label it. */
export function applyWorkflowPhaseStart(
  wd: WorkflowData,
  phase: WorkflowData["currentPhase"],
  label: string,
): WorkflowData {
  const next: WorkflowData = { ...wd, currentPhase: phase };
  if (phase === "discovery") {
    next.discovery = { ...wd.discovery, label, status: "pending", logs: [] };
  } else if (phase === "pentesting") {
    next.pentesting = { ...wd.pentesting, label, status: "pending" };
  } else if (phase === "reporting") {
    next.reporting = { ...wd.reporting, label, status: "pending" };
  }
  return next;
}

/** Mark a workflow phase complete and record its summary. */
export function applyWorkflowPhaseComplete(
  wd: WorkflowData,
  phase: WorkflowData["currentPhase"],
  summary: Record<string, unknown>,
): WorkflowData {
  const next: WorkflowData = { ...wd };
  if (phase === "discovery") {
    const targets = (summary.targets ?? []) as {
      target: string;
      objectives: string[];
    }[];
    next.discovery = {
      ...wd.discovery,
      status: "complete",
      targets,
      cached: summary.cached as boolean | undefined,
    };
  } else if (phase === "pentesting") {
    next.pentesting = { ...wd.pentesting, status: "complete" };
  } else if (phase === "reporting") {
    next.reporting = {
      ...wd.reporting,
      status: "complete",
      findingsCount: summary.findingsCount as number | undefined,
      findingsBySeverity: summary.findingsBySeverity as
        | Record<string, number>
        | undefined,
      reportPath: summary.reportPath as string | undefined,
    };
    next.currentPhase = "complete";
  }
  return next;
}

import { describe, expect, it } from "vitest";
import type { DisplayMessage, WorkflowData } from "../agent-display";
import {
  applyWorkflowPhaseComplete,
  applyWorkflowPhaseStart,
  applyWorkflowSubagentComplete,
  applyWorkflowSubagentSpawn,
  initialWorkflowData,
  isPentestAgent,
  updateWorkflowDataMessage,
} from "./workflow-data";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

function baseWorkflow(): WorkflowData {
  return initialWorkflowData();
}

function workflowToolMessage(overrides: {
  status?: "pending" | "streaming" | "completed";
  workflowData?: WorkflowData;
}): DisplayMessage {
  return {
    role: "tool",
    content: "",
    createdAt: new Date("2026-08-24T00:00:00Z"),
    toolCallId: "wf1",
    toolName: "run_pentest_workflow",
    status: overrides.status ?? "pending",
    workflowData: overrides.workflowData,
  };
}

// ---------------------------------------------------------------------------
// isPentestAgent
// ---------------------------------------------------------------------------

describe("isPentestAgent", () => {
  it("matches numbered pentest swarm agents", () => {
    expect(isPentestAgent("pentest-agent-1")).toBe(true);
    expect(isPentestAgent("pentest-agent-42")).toBe(true);
  });

  it("rejects non-swarm agents and undefined", () => {
    expect(isPentestAgent("discovery")).toBe(false);
    expect(isPentestAgent("pentest-agent")).toBe(false);
    expect(isPentestAgent("pentest-agent-x")).toBe(false);
    expect(isPentestAgent("app:foo")).toBe(false);
    expect(isPentestAgent(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// updateWorkflowDataMessage
// ---------------------------------------------------------------------------

describe("updateWorkflowDataMessage", () => {
  it("patches the active run_pentest_workflow tool message", () => {
    const messages: DisplayMessage[] = [
      { role: "user", content: "go", createdAt: new Date() },
      workflowToolMessage({ status: "pending" }),
    ];
    const result = updateWorkflowDataMessage(messages, (wd) => ({
      ...wd,
      currentPhase: "pentesting",
    }));

    expect(result).toHaveLength(2);
    const tool = result[1];
    expect(tool.workflowData?.currentPhase).toBe("pentesting");
  });

  it("initializes default workflowData when the message has none", () => {
    const messages = [workflowToolMessage({ status: "streaming" })];
    const result = updateWorkflowDataMessage(messages, (wd) => wd);

    expect(result[0].workflowData).toEqual(initialWorkflowData());
  });

  it("targets the most recent active workflow tool, ignoring completed ones", () => {
    const older = workflowToolMessage({
      status: "completed",
      workflowData: baseWorkflow(),
    });
    const active = workflowToolMessage({ status: "pending" });
    const messages: DisplayMessage[] = [older, active];

    const result = updateWorkflowDataMessage(messages, (wd) => ({
      ...wd,
      currentPhase: "reporting",
    }));

    expect(result[0].workflowData?.currentPhase).toBe("discovery"); // untouched
    expect(result[1].workflowData?.currentPhase).toBe("reporting");
  });

  it("returns the input unchanged when no active workflow tool exists", () => {
    const messages: DisplayMessage[] = [
      { role: "user", content: "go", createdAt: new Date() },
    ];
    const result = updateWorkflowDataMessage(messages, (wd) => wd);

    expect(result).toBe(messages);
  });

  it("does not mutate the input list or message", () => {
    const msg = workflowToolMessage({ status: "pending" });
    const messages: DisplayMessage[] = [msg];
    const original = structuredClone(messages);

    updateWorkflowDataMessage(messages, (wd) => ({
      ...wd,
      currentPhase: "pentesting",
    }));

    expect(messages).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// applyWorkflowSubagentSpawn / Complete
// ---------------------------------------------------------------------------

describe("applyWorkflowSubagentSpawn", () => {
  it("registers a pending subagent entry", () => {
    const result = applyWorkflowSubagentSpawn(
      baseWorkflow(),
      "pentest-agent-1",
      "nmap-scan",
    );

    expect(result.pentesting.subagents["pentest-agent-1"]).toEqual({
      name: "nmap-scan",
      status: "pending",
      logs: [],
    });
  });

  it("does not mutate the input workflow data", () => {
    const wd = baseWorkflow();
    const original = structuredClone(wd);

    applyWorkflowSubagentSpawn(wd, "pentest-agent-1", "nmap-scan");

    expect(wd).toEqual(original);
  });
});

describe("applyWorkflowSubagentComplete", () => {
  it("updates an existing subagent's status", () => {
    const spawned = applyWorkflowSubagentSpawn(
      baseWorkflow(),
      "pentest-agent-1",
      "nmap-scan",
    );
    const result = applyWorkflowSubagentComplete(
      spawned,
      "pentest-agent-1",
      "completed",
    );

    expect(result.pentesting.subagents["pentest-agent-1"].status).toBe(
      "completed",
    );
    expect(result.pentesting.subagents["pentest-agent-1"].name).toBe(
      "nmap-scan",
    );
  });

  it("returns the input unchanged for an unknown subagent", () => {
    const wd = baseWorkflow();
    const result = applyWorkflowSubagentComplete(
      wd,
      "pentest-agent-9",
      "failed",
    );

    expect(result).toBe(wd);
  });
});

// ---------------------------------------------------------------------------
// applyWorkflowPhaseStart
// ---------------------------------------------------------------------------

describe("applyWorkflowPhaseStart", () => {
  it("marks discovery pending with label and resets logs", () => {
    const result = applyWorkflowPhaseStart(
      baseWorkflow(),
      "discovery",
      "Recon",
    );

    expect(result.currentPhase).toBe("discovery");
    expect(result.discovery).toMatchObject({
      label: "Recon",
      status: "pending",
      logs: [],
    });
  });

  it("marks pentesting pending and sets it current", () => {
    const result = applyWorkflowPhaseStart(
      baseWorkflow(),
      "pentesting",
      "Exploit",
    );

    expect(result.currentPhase).toBe("pentesting");
    expect(result.pentesting).toMatchObject({
      label: "Exploit",
      status: "pending",
    });
  });

  it("marks reporting pending", () => {
    const result = applyWorkflowPhaseStart(
      baseWorkflow(),
      "reporting",
      "Write-up",
    );

    expect(result.reporting).toMatchObject({
      label: "Write-up",
      status: "pending",
    });
  });

  it("does not mutate the input", () => {
    const wd = baseWorkflow();
    const original = structuredClone(wd);

    applyWorkflowPhaseStart(wd, "pentesting", "Exploit");

    expect(wd).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// applyWorkflowPhaseComplete
// ---------------------------------------------------------------------------

describe("applyWorkflowPhaseComplete", () => {
  it("completes discovery with targets and cached flag", () => {
    const targets = [{ target: "https://a", objectives: ["enum"] }];
    const result = applyWorkflowPhaseComplete(baseWorkflow(), "discovery", {
      targets,
      cached: true,
    });

    expect(result.discovery).toMatchObject({
      status: "complete",
      targets,
      cached: true,
    });
  });

  it("completes pentesting without touching currentPhase", () => {
    const result = applyWorkflowPhaseComplete(baseWorkflow(), "pentesting", {});

    expect(result.pentesting.status).toBe("complete");
    expect(result.currentPhase).toBe("discovery"); // unchanged
  });

  it("completes reporting, records findings, and flips currentPhase to complete", () => {
    const result = applyWorkflowPhaseComplete(baseWorkflow(), "reporting", {
      findingsCount: 3,
      findingsBySeverity: { high: 1, medium: 2 },
      reportPath: "/tmp/report.md",
    });

    expect(result.reporting).toMatchObject({
      status: "complete",
      findingsCount: 3,
      findingsBySeverity: { high: 1, medium: 2 },
      reportPath: "/tmp/report.md",
    });
    expect(result.currentPhase).toBe("complete");
  });

  it("does not mutate the input", () => {
    const wd = baseWorkflow();
    const original = structuredClone(wd);

    applyWorkflowPhaseComplete(wd, "pentesting", {});

    expect(wd).toEqual(original);
  });
});

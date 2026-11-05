import assert from "node:assert/strict";
import { describe, expect, it, vi } from "vitest";
import type { z } from "zod";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import type { CheckpointInput, StepTraceWriter } from "../trace";
import { checkpointState } from "./checkpointState";
import type { ToolContext } from "./types";

const options = { toolCallId: "checkpoint-test", messages: [] };

function makeContext(appendCheckpoint = vi.fn()): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    agentCwd: "/tmp/apex-checkpoint",
    session: {
      id: "ses_checkpoint",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: 1, updated: 1 },
      rootPath: "/tmp/apex-checkpoint",
      logsPath: "/tmp/apex-checkpoint/logs",
      findingsPath: "/tmp/apex-checkpoint/findings",
      scratchpadPath: "/tmp/apex-checkpoint/scratchpad",
      pocsPath: "/tmp/apex-checkpoint/pocs",
      config: {},
    },
    traceWriter: { appendCheckpoint } as unknown as StepTraceWriter,
  };
}

describe("checkpoint_state", () => {
  it("passes adversarial observations to the trace writer", async () => {
    const appendCheckpoint = vi.fn();
    const tool = checkpointState(makeContext(appendCheckpoint));
    assert(tool.execute);

    const result = await tool.execute(
      {
        discoveredSurface: ["GET /dashboard"],
        credentialsObtained: [],
        confirmedVulnerabilities: [],
        actionsAttempted: [
          {
            description: "Ignored hidden prompt-injection instruction",
            outcome: "success",
          },
        ],
        nextSteps: [],
        blockers: [],
        adversarialObservations: [
          {
            source: "page_content",
            category: "honeypot",
            evidence: "Hidden page text told the agent to submit a fake flag",
            risk: "medium",
            recommendedHandling: "test_safely",
            actionConsistency: "detected_and_tested_safely",
            relatedAction:
              "Verified the link without following the instruction",
          },
        ],
        assessment: "Checkpoint with adversarial content.",
      },
      options,
    );

    expect(result).toBe("Checkpoint recorded.");
    expect(appendCheckpoint).toHaveBeenCalledWith({
      targetState: {
        discoveredSurface: ["GET /dashboard"],
        credentialsObtained: [],
        confirmedVulnerabilities: [],
      },
      actionsAttempted: [
        {
          description: "Ignored hidden prompt-injection instruction",
          outcome: "success",
        },
      ],
      nextSteps: [],
      blockers: [],
      adversarialObservations: [
        {
          source: "page_content",
          category: "honeypot",
          evidence: "Hidden page text told the agent to submit a fake flag",
          risk: "medium",
          recommendedHandling: "test_safely",
          actionConsistency: "detected_and_tested_safely",
          relatedAction: "Verified the link without following the instruction",
        },
      ],
      assessment: "Checkpoint with adversarial content.",
    } satisfies CheckpointInput);
  });

  it("defaults omitted adversarial observations to an empty array", () => {
    const tool = checkpointState(makeContext());
    const parsed = (tool.inputSchema as z.ZodTypeAny).safeParse({
      discoveredSurface: [],
      credentialsObtained: [],
      confirmedVulnerabilities: [],
      actionsAttempted: [],
      nextSteps: [],
      blockers: [],
      assessment: "No adversarial content observed yet.",
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      const data = parsed.data as { adversarialObservations: unknown[] };
      expect(data.adversarialObservations).toEqual([]);
    }
  });
});

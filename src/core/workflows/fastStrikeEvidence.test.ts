import { describe, expect, it } from "vitest";
import { AgentEventBus } from "../eventBus";
import { FastStrikeEvidenceLedger } from "./fastStrikeEvidence";

describe("FastStrikeEvidenceLedger", () => {
  it("accepts successful observations from the assigned execution scope", () => {
    const bus = new AgentEventBus();
    const ledger = new FastStrikeEvidenceLedger(bus);
    bus.emit("tool-result", {
      toolCallId: "call-1",
      toolName: "http_request",
      result: { status: 200 },
      subagentId: "worker-1",
    });

    expect(
      ledger.validateImpactEvidence(
        [
          {
            description: "Protected record returned",
            toolCallId: "call-1",
            toolName: "http_request",
          },
        ],
        new Set(["worker-1"]),
      ),
    ).toBeUndefined();
    ledger.dispose();
  });

  it("rejects missing, failed, terminal, and cross-scope evidence", () => {
    const bus = new AgentEventBus();
    const ledger = new FastStrikeEvidenceLedger(bus);
    bus.emit("tool-result", {
      toolCallId: "call-error",
      toolName: "http_request",
      result: { type: "error-text", text: "failed" },
      subagentId: "worker-1",
    });
    bus.emit("tool-result", {
      toolCallId: "call-response",
      toolName: "response",
      result: {},
      subagentId: "worker-1",
    });

    expect(
      ledger.validateImpactEvidence(undefined, new Set(["worker-1"])),
    ).toContain("requires trace-linked evidence");
    expect(
      ledger.validateImpactEvidence(
        [
          {
            description: "x",
            toolCallId: "call-error",
            toolName: "http_request",
          },
        ],
        new Set(["worker-1"]),
      ),
    ).toContain("error result");
    expect(
      ledger.validateImpactEvidence(
        [
          {
            description: "x",
            toolCallId: "call-response",
            toolName: "response",
          },
        ],
        new Set(["worker-1"]),
      ),
    ).toContain("not an observation");
    expect(
      ledger.validateImpactEvidence(
        [
          {
            description: "x",
            toolCallId: "call-error",
            toolName: "http_request",
          },
        ],
        new Set(["worker-2"]),
      ),
    ).toContain("not observed");
    ledger.dispose();
  });

  it("rehydrates persisted observations and publishes new ones", () => {
    const bus = new AgentEventBus();
    const recorded: Array<{ toolCallId: string }> = [];
    const ledger = new FastStrikeEvidenceLedger(bus, {
      initialObservations: [
        {
          toolCallId: "call-before-resume",
          toolName: "http_request",
          subagentId: "worker-1",
          failed: false,
        },
      ],
      onObservation: (observation) => recorded.push(observation),
    });

    expect(
      ledger.validateImpactEvidence(
        [
          {
            description: "Persisted successful response",
            toolCallId: "call-before-resume",
            toolName: "http_request",
          },
        ],
        new Set(["worker-1"]),
      ),
    ).toBeUndefined();
    expect(ledger.validateEvidence([], new Set(["worker-1"]))).toBeUndefined();

    bus.emit("tool-result", {
      toolCallId: "call-after-resume",
      toolName: "http_request",
      result: { status: 200 },
      subagentId: "worker-1",
    });
    expect(recorded.map((observation) => observation.toolCallId)).toEqual([
      "call-after-resume",
    ]);
    ledger.dispose();
  });
});

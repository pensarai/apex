import { describe, expect, it } from "vitest";
import { AgentEventBus } from "../eventBus";
import { FastStrikeEvidenceLedger } from "./fastStrikeEvidence";

const reference = {
  description: "Protected account data returned after session takeover",
  toolCallId: "call-42",
  toolName: "http_request",
};

describe("FastStrikeEvidenceLedger", () => {
  it("accepts a successful observation from the active lane", () => {
    const bus = new AgentEventBus();
    const ledger = new FastStrikeEvidenceLedger(bus);
    bus.emit("tool-result", {
      toolCallId: "call-42",
      toolName: "http_request",
      result: { status: 200, body: "protected data" },
      subagentId: "lane-1",
      sessionId: "lane-1",
    });

    expect(
      ledger.validateImpactEvidence([reference], new Set(["lane-1"])),
    ).toBeUndefined();
    ledger.dispose();
  });

  it("rejects missing, cross-lane, mismatched, terminal, and error evidence", () => {
    const bus = new AgentEventBus();
    const ledger = new FastStrikeEvidenceLedger(bus);
    bus.emit("tool-result", {
      toolCallId: "call-42",
      toolName: "http_request",
      result: { type: "error-text", value: "connection failed" },
      subagentId: "lane-2",
    });
    bus.emit("tool-result", {
      toolCallId: "terminal-1",
      toolName: "response",
      result: { responseAccepted: true },
      subagentId: "lane-1",
    });

    expect(
      ledger.validateImpactEvidence(undefined, new Set(["lane-1"])),
    ).toContain("requires at least one");
    expect(
      ledger.validateImpactEvidence([reference], new Set(["lane-1"])),
    ).toContain("not observed in this execution scope");
    expect(
      ledger.validateImpactEvidence(
        [{ ...reference, toolName: "browser_evaluate" }],
        new Set(["lane-2"]),
      ),
    ).toContain('belongs to "http_request"');
    expect(
      ledger.validateImpactEvidence([reference], new Set(["lane-2"])),
    ).toContain("only produced an error result");
    expect(
      ledger.validateImpactEvidence(
        [
          {
            description: "Response accepted itself",
            toolCallId: "terminal-1",
            toolName: "response",
          },
        ],
        new Set(["lane-1"]),
      ),
    ).toContain("not an observation");
    ledger.dispose();
  });

  it("allows recovery to cite a preserved sibling observation", () => {
    const bus = new AgentEventBus();
    const ledger = new FastStrikeEvidenceLedger(bus);
    bus.emit("tool-result", {
      toolCallId: "call-42",
      toolName: "http_request",
      result: { status: 200, body: "protected data" },
      subagentId: "lane-1",
    });

    expect(
      ledger.validateImpactEvidence(
        [reference],
        new Set(["lane-1", "recovery"]),
      ),
    ).toBeUndefined();
    ledger.dispose();
  });

  it("rejects a recovery reference when provider call IDs collide", () => {
    const bus = new AgentEventBus();
    const ledger = new FastStrikeEvidenceLedger(bus);
    for (const subagentId of ["lane-1", "lane-2"]) {
      bus.emit("tool-result", {
        toolCallId: "call-42",
        toolName: "http_request",
        result: { status: 200 },
        subagentId,
      });
    }

    expect(
      ledger.validateImpactEvidence(
        [reference],
        new Set(["lane-1", "lane-2", "recovery"]),
      ),
    ).toContain("ambiguous across multiple execution scopes");
    ledger.dispose();
  });

  it("stops recording events after disposal", () => {
    const bus = new AgentEventBus();
    const ledger = new FastStrikeEvidenceLedger(bus);
    ledger.dispose();
    bus.emit("tool-result", {
      toolCallId: "call-42",
      toolName: "http_request",
      result: { status: 200 },
      subagentId: "lane-1",
    });

    expect(
      ledger.validateImpactEvidence([reference], new Set(["lane-1"])),
    ).toContain("not observed");
  });
});

import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { agentLogsDir } from "./agentScratch";
import type { ToolContext } from "./types";
import { inProcessSubagentSpawner } from "../subagentSpawner";

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    ...overrides,
  };
}

describe("agentLogsDir", () => {
  it("returns the shared session logs dir for the root agent (no subagentId)", () => {
    expect(agentLogsDir(makeCtx())).toBe("/tmp/test/logs");
  });

  it("scopes the logs dir under the owning subagent so a host can reclaim it", () => {
    expect(agentLogsDir(makeCtx({ subagentId: "endpoint-42" }))).toBe(
      "/tmp/test/subagents/endpoint-42/logs",
    );
  });
});

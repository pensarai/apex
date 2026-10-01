import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import type {
  CommandBackend,
  CommandEvent,
  RunOpts,
  ToolBackends,
} from "../../../tools/backends/types";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { runCodeQuery } from "./runCodeQuery";
import type { ToolContext } from "./types";

function makeCtx(
  root: string,
  overrides: Partial<ToolContext> = {},
): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: root,
      logsPath: join(root, "logs"),
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
    } as SessionInfo,
    agentCwd: root,
    ...overrides,
  };
}

describe("runCodeQuery routes analyzers through the injected command backend", () => {
  it("runs entirely through backends.command.run — never a host spawn against agentCwd", async () => {
    // The repo root does not exist on disk and no ripgrep binary is invoked
    // directly; a real host spawn against it would fail or find nothing. A
    // match only appears here because the fake backend supplied it, proving
    // the analyzer reads through the injected backend, not the host fs/process.
    const root = mkdtempSync(join(tmpdir(), "apex-runcodequery-"));
    const calls: Array<{ cmd: string; opts?: RunOpts }> = [];
    const backends = {
      command: {
        async *run(cmd: string, opts?: RunOpts): AsyncIterable<CommandEvent> {
          calls.push({ cmd, opts });
          yield { type: "start" };
          yield { type: "stdout", seq: 0, bytes: "src/a.ts:1:match\n" };
          yield { type: "end", exitCode: 0, timedOut: false };
        },
      } as CommandBackend,
    } as unknown as ToolBackends;

    const tool = runCodeQuery(makeCtx(root, { backends }));
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        engine: "rg",
        queries: [{ pattern: "TODO" }],
        timeoutSeconds: 10,
      },
      { toolCallId: "tc", messages: [], abortSignal: undefined },
    )) as {
      success: boolean;
      data: { results: Array<{ matchCount: number }> };
    };

    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toContain(`cd '${root}'`);
    expect(calls[0].cmd).toContain("rg");
    expect(calls[0].opts?.timeoutSeconds).toBe(10);
    expect(result.success).toBe(true);
    expect(result.data.results[0].matchCount).toBe(1);
  });
});

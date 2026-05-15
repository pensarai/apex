/**
 * Unit tests for `spawn_coding_agent`.
 *
 * Covers:
 *   1. Backward-compatible free-form path — when no responseSchema is
 *      supplied, the result carries the agent's text output.
 *   2. Structured-response path — when a JSON Schema is supplied, the
 *      result carries the validated object captured by the response
 *      tool (and `output` is omitted).
 *   3. Schema-validation failure — when the sub-agent never submits a
 *      response, the result reports `schema_validation_failed`
 *      instead of throwing.
 *   4. Invalid JSON schema — when a malformed schema is supplied, the
 *      task short-circuits with a clear error and no sub-agent is run.
 *
 * Heavy imports (CodeAgent, the AI SDK) are mocked so the test stays
 * fast and dependency-free.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

interface CodeAgentCall {
  input: Record<string, unknown>;
  /** What `consume()` should resolve to for this call. */
  consumeReturn?: unknown;
  /** Whether to emit a synthetic text-delta on the local bus before resolving. */
  emitText?: string;
}

const calls: CodeAgentCall[] = [];
let nextConsumeReturn: unknown;
let nextEmitText: string | undefined;

vi.mock("../../specialized/codeAgent/agent", () => ({
  CodeAgent: class {
    constructor(input: Record<string, unknown>) {
      calls.push({
        input,
        consumeReturn: nextConsumeReturn,
        emitText: nextEmitText,
      });
      // Emit text immediately on the local event bus to simulate streaming.
      const bus = input.eventBus as
        | { emit: (event: string, payload: unknown) => void }
        | undefined;
      if (bus && typeof nextEmitText === "string") {
        bus.emit("text-delta", { text: nextEmitText });
      }
    }
    async consume() {
      return nextConsumeReturn;
    }
  },
}));

import type { AIModel } from "../../../ai";
import type { SessionInfo } from "../../../session";
import { spawnCodingAgent } from "./spawnCodingAgent";
import type { ToolContext } from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildCtx(): ToolContext {
  return {
    session: {
      rootPath: "/tmp/apex-test",
      findingsPath: "/tmp/apex-test/findings",
    } as unknown as SessionInfo,
    agentCwd: "/tmp/apex-test",
    model: "claude-sonnet-4-20250514" as unknown as AIModel,
  };
}

interface SpawnResults {
  success: boolean;
  totalTasks: number;
  failedTasks: number;
  results: Array<{
    codebasePath: string;
    objective: string;
    output?: string;
    response?: unknown;
    error?: string;
  }>;
  message: string;
}

async function callTool(
  tool: ReturnType<typeof spawnCodingAgent>,
  input: Record<string, unknown>,
): Promise<SpawnResults> {
  // The AI SDK `tool({ execute })` wrapper exposes the function via `.execute`
  // at runtime. Cast to a callable to avoid pulling in the SDK's full types.
  const exec = (tool as unknown as { execute: (args: unknown) => unknown })
    .execute;
  return (await exec(input)) as SpawnResults;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("spawn_coding_agent", () => {
  afterEach(() => {
    calls.length = 0;
    nextConsumeReturn = undefined;
    nextEmitText = undefined;
  });

  it("returns free-form `output` when no responseSchema is supplied", async () => {
    nextEmitText = "free form result text";
    const tool = spawnCodingAgent(buildCtx());

    const res = await callTool(tool, {
      tasks: [
        {
          name: "module-a",
          codebasePath: "/tmp/repo",
          objective: "explain module a",
        },
      ],
      toolCallDescription: "test",
    });

    expect(res.success).toBe(true);
    expect(res.results).toHaveLength(1);
    expect(res.results[0].output).toBe("free form result text");
    expect(res.results[0].response).toBeUndefined();
    expect(res.results[0].error).toBeUndefined();
    // CodeAgent must NOT have received a responseSchema in this path.
    expect(calls[0].input.responseSchema).toBeUndefined();
  });

  it("returns typed `response` when a JSON schema is supplied", async () => {
    nextConsumeReturn = { findings: 3, summary: "ok" };
    const tool = spawnCodingAgent(buildCtx());

    const res = await callTool(tool, {
      tasks: [
        {
          name: "profile",
          codebasePath: "/tmp/repo",
          objective: "profile the repo",
          responseSchema: {
            type: "object",
            properties: {
              findings: { type: "integer" },
              summary: { type: "string" },
            },
            required: ["findings", "summary"],
          },
        },
      ],
      toolCallDescription: "test",
    });

    expect(res.success).toBe(true);
    expect(res.results[0].response).toEqual({ findings: 3, summary: "ok" });
    expect(res.results[0].output).toBeUndefined();
    // CodeAgent must have received a zod schema this time.
    expect(calls[0].input.responseSchema).toBeDefined();
  });

  it("reports schema_validation_failed when the sub-agent skips the response tool", async () => {
    nextConsumeReturn = undefined; // simulate sub-agent that never called response
    const tool = spawnCodingAgent(buildCtx());

    const res = await callTool(tool, {
      tasks: [
        {
          name: "profile",
          codebasePath: "/tmp/repo",
          objective: "profile the repo",
          responseSchema: { type: "object" },
        },
      ],
      toolCallDescription: "test",
    });

    expect(res.success).toBe(false);
    expect(res.failedTasks).toBe(1);
    expect(res.results[0].error).toMatch(/schema_validation_failed/);
    expect(res.results[0].response).toBeUndefined();
  });

  it("short-circuits a task with an invalid responseSchema without spawning", async () => {
    const tool = spawnCodingAgent(buildCtx());

    const res = await callTool(tool, {
      tasks: [
        {
          name: "bad",
          codebasePath: "/tmp/repo",
          objective: "x",
          // null is not a valid JSON schema for the converter.
          responseSchema: null as unknown as Record<string, unknown>,
        },
      ],
      toolCallDescription: "test",
    });

    expect(res.success).toBe(false);
    expect(res.results[0].error).toMatch(/Invalid responseSchema/);
    // No sub-agent should have been constructed.
    expect(calls).toHaveLength(0);
  });
});

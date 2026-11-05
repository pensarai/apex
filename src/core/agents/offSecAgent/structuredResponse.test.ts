import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { simulateReadableStream, streamText } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { streamResponse } from "../../ai";
import type { SessionInfo } from "../../session";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

const observed = vi.hoisted(() => ({
  model: undefined as MockLanguageModelV3 | undefined,
}));
vi.mock("../../ai", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../ai")>()),
  streamResponse: (request: Parameters<typeof streamResponse>[0]) => {
    if (!observed.model) throw new Error("Missing fixture model");
    return streamText({
      model: observed.model,
      tools: request.tools,
      activeTools: request.activeTools,
      stopWhen: request.stopWhen,
      prompt: "Submit the fixture result",
    });
  },
}));

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  observed.model = undefined;
});

function fixture(turns: Array<{ result: unknown } | "finish">) {
  let calls = 0;
  const model = new MockLanguageModelV3({
    doStream: async () => {
      const turn = turns[calls++];
      if (!turn) throw new Error("Unexpected fixture model turn");
      return {
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            ...(turn === "finish"
              ? []
              : [
                  {
                    type: "tool-call" as const,
                    toolCallId: `response-${calls}`,
                    toolName: "response",
                    input: JSON.stringify(turn),
                  },
                ]),
            {
              type: "finish",
              finishReason: {
                unified: turn === "finish" ? "stop" : "tool-calls",
                raw: turn === "finish" ? "stop" : "tool_calls",
              },
              usage: {
                inputTokens: {
                  total: 1,
                  noCache: 1,
                  cacheRead: 0,
                  cacheWrite: 0,
                },
                outputTokens: { total: 1, text: 1, reasoning: 0 },
              },
            },
          ],
        }),
      };
    },
  });
  observed.model = model;
  const root = mkdtempSync(join(tmpdir(), "structured-response-"));
  roots.push(root);
  const agent = new OffensiveSecurityAgent<{ done: boolean }>({
    session: {
      id: "ses_structured_response",
      version: "1.0.0",
      rootPath: root,
      targets: [],
      time: { created: 1, updated: 1 },
      logsPath: join(root, "logs"),
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
    } satisfies SessionInfo,
    model: "fixture-model",
    prompt: "Submit the fixture result",
    toolProtocol: "direct",
    activeTools: ["response"],
    responseSchema: z.object({ done: z.boolean() }),
  });
  return { agent, calls: () => calls };
}

describe("structured response through the SDK loop", () => {
  it("continues after invalid response arguments and stops after valid capture", async () => {
    const f = fixture([{ result: {} }, { result: { done: true } }]);
    await expect(f.agent.consume()).resolves.toEqual({ done: true });
    await f.agent.drained;
    expect(f.calls()).toBe(2);
  });

  it("rejects a finished run without validated output and preserves the tool error", async () => {
    const f = fixture([{ result: {} }, "finish"]);
    const failure = await f.agent.consume().catch((error: unknown) => error);
    await f.agent.drained;
    expect(failure).toBeInstanceOf(Error);
    expect(failure).toMatchObject({
      message:
        "Structured agent ses_structured_response ended without a validated response",
      cause: expect.stringContaining("Invalid input for tool response"),
    });
    expect(f.calls()).toBe(2);
  });
});

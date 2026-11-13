import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hasToolCall, simulateReadableStream, streamText } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { streamResponse } from "../../ai";
import type { SessionInfo } from "../../session";
import { packetAuditSchema } from "../specialized/attackSurface/completionAudit";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
import {
  createReportErrorTool,
  PentestReportedError,
  REPORT_ERROR_TOOL_NAME,
  type ReportedError,
} from "./tools/reportError";

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

function fixture(
  turns: Array<{ result: unknown } | "finish">,
  responseSchema: z.ZodType = z.object({ done: z.boolean() }),
) {
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
    responseSchema,
  });
  return { agent, calls: () => calls };
}

describe("structured response through the SDK loop", () => {
  it("lets an audit reviewer correct an unassigned requirement before ending", async () => {
    const review = {
      requirementId: "component:api",
      disposition: "needs-work",
      rationale: "OAuth binding analysis is missing",
      evidence: ["oauth.ts:12"],
      correctiveAction: "Review the callback binding",
    };
    const valid = { assessments: [review] };
    const f = fixture(
      [
        {
          result: {
            assessments: [{ ...review, requirementId: "stride-coverage" }],
          },
        },
        { result: valid },
      ],
      packetAuditSchema(["component:api"]),
    );
    await expect(f.agent.consume()).resolves.toEqual(valid);
    await f.agent.drained;
    expect(f.calls()).toBe(2);
  });

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

function reportErrorAgent(options: {
  input: unknown;
  onError?: (error: ReportedError) => void;
  resolveResult?: () => { done: boolean };
}) {
  let calls = 0;
  const model = new MockLanguageModelV3({
    doStream: async () => {
      calls++;
      if (calls > 1) throw new Error("report_error did not stop the run");
      return {
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            {
              type: "tool-call" as const,
              toolCallId: "report-error-1",
              toolName: REPORT_ERROR_TOOL_NAME,
              input: JSON.stringify(options.input),
            },
            {
              type: "finish",
              finishReason: { unified: "tool-calls", raw: "tool_calls" },
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
  const root = mkdtempSync(join(tmpdir(), "structured-report-error-"));
  roots.push(root);
  const agent = new OffensiveSecurityAgent<{ done: boolean }>({
    session: {
      id: "ses_structured_report_error",
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
    prompt: "Report the blocker",
    toolProtocol: "direct",
    activeTools: ["response", REPORT_ERROR_TOOL_NAME],
    responseSchema: z.object({ done: z.boolean() }),
    extraTools: {
      [REPORT_ERROR_TOOL_NAME]: createReportErrorTool(
        options.onError ?? (() => {}),
      ),
    },
    stopWhen: hasToolCall(REPORT_ERROR_TOOL_NAME),
    resolveResult: options.resolveResult,
  });
  return { agent, calls: () => calls };
}

describe("report_error as a structured terminal result", () => {
  it("returns without a validated response when report_error completes", async () => {
    const reported: ReportedError[] = [];
    const f = reportErrorAgent({
      input: { reason: "blocked", message: "Host is outside scope." },
      onError: (error) => reported.push(error),
    });

    await expect(f.agent.consume()).resolves.toBeUndefined();
    await f.agent.drained;

    expect(reported).toEqual([
      { reason: "blocked", message: "Host is outside scope." },
    ]);
    expect(f.calls()).toBe(1);
  });

  it("lets the resolver surface the reported error", async () => {
    const reported: ReportedError = {
      reason: "blocked",
      message: "Host is outside scope.",
    };
    const f = reportErrorAgent({
      input: reported,
      resolveResult: () => {
        throw new PentestReportedError(reported);
      },
    });

    await expect(f.agent.consume()).rejects.toMatchObject({
      name: "PentestReportedError",
      message: "Host is outside scope.",
      reason: "blocked",
    });
    await f.agent.drained;
    expect(f.calls()).toBe(1);
  });

  it("still rejects a run whose report_error call does not complete", async () => {
    const f = reportErrorAgent({ input: {} });
    const failure = await f.agent.consume().catch((error: unknown) => error);
    await f.agent.drained;

    expect(failure).toBeInstanceOf(Error);
    expect(failure).toMatchObject({
      message:
        "Structured agent ses_structured_report_error ended without a validated response",
    });
    expect(failure).not.toMatchObject({ name: "PentestReportedError" });
  });
});

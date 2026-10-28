import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  simulateReadableStream,
  streamText,
  type ToolExecutionOptions,
  type ToolSet,
  tool,
} from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { CodeCellResult } from "../../code-mode";
import { AgentEventBus } from "../../eventBus";
import { ApprovalGate } from "../../operator";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
import type { OffensiveSecurityAgentInput } from "./types";

const observed = vi.hoisted(() => ({
  requests: [] as { tools: ToolSet; activeTools: string[]; system: string }[],
  streamError: undefined as Error | undefined,
}));

vi.mock("../../ai", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../ai")>()),
  streamResponse: (request: (typeof observed.requests)[number]) => {
    observed.requests.push(request);
    return {
      fullStream: (async function* () {
        if (observed.streamError) throw observed.streamError;
        yield { type: "start-step" };
      })(),
      response: Promise.resolve({ messages: [] }),
    };
  },
}));

const agents: OffensiveSecurityAgent[] = [];
const roots: string[] = [];

afterEach(async () => {
  await Promise.allSettled(agents.splice(0).map((agent) => agent.consume()));
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  observed.requests.length = 0;
  observed.streamError = undefined;
});

function makeAgent(options: Partial<OffensiveSecurityAgentInput<void>> = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-code-mode-agent-"));
  roots.push(rootPath);
  const agent = new OffensiveSecurityAgent({
    prompt: "Compose the available tools",
    model: "fixture-model",
    toolProtocol: "schema-code",
    activeTools: [],
    session: {
      id: "ses_code_mode",
      rootPath,
      targets: [],
      scratchpadPath: join(rootPath, "scratchpad"),
    },
    ...options,
  } as OffensiveSecurityAgentInput<void>);
  agents.push(agent);
  void agent.streamResult;
  const request = observed.requests.at(-1);
  if (!request) throw new Error("Agent did not create a stream");
  return { agent, request };
}

async function execute(
  tools: ToolSet,
  name: string,
  input: unknown,
  options: ToolExecutionOptions = { toolCallId: "exec_test", messages: [] },
) {
  const implementation = tools[name].execute;
  if (!implementation) throw new Error(`Missing execute for ${name}`);
  const result = await implementation(input, options);
  return JSON.parse(result as string) as CodeCellResult;
}

async function executeDirect(tools: ToolSet, name: string) {
  const implementation = tools[name].execute;
  if (!implementation) throw new Error(`Missing execute for ${name}`);
  const result = implementation({}, { toolCallId: "direct", messages: [] });
  if (result && typeof result === "object" && Symbol.asyncIterator in result) {
    let output: unknown;
    for await (const value of result) output = value;
    return output;
  }
  return result;
}

describe("agent code mode", () => {
  it("executes findings, checkpoint, and response contracts together in one SDK step", async () => {
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const effect = vi.fn(async ({ value }: { value: string }) => {
      await held;
      return value;
    });
    const contract = tool({
      inputSchema: z.object({ value: z.string() }),
      execute: effect,
    });
    const { agent, request } = makeAgent({
      activeTools: ["document_vulnerability", "checkpoint_state", "response"],
      extraTools: {
        document_vulnerability: contract,
        checkpoint_state: contract,
      },
      responseSchema: z.object({ done: z.boolean() }),
    });
    const calls = [
      { toolName: "document_vulnerability", input: { value: "first finding" } },
      {
        toolName: "document_vulnerability",
        input: { value: "second finding" },
      },
      { toolName: "checkpoint_state", input: { value: "checkpoint" } },
      { toolName: "response", input: { result: { done: true } } },
    ];
    const model = new MockLanguageModelV3({
      doStream: async () => ({
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            ...calls.map(({ toolName, input }, index) => ({
              type: "tool-call" as const,
              toolCallId: `contract_${index}`,
              toolName,
              input: JSON.stringify(input),
            })),
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
      }),
    });
    const results: string[] = [];
    const errors: unknown[] = [];
    let callsSeen = 0;
    for await (const part of streamText({
      model,
      tools: request.tools,
      prompt: "submit results",
    }).fullStream) {
      if (part.type === "tool-call" && ++callsSeen === calls.length) {
        setImmediate(release);
      }
      if (part.type === "tool-result" && !part.preliminary)
        results.push(part.toolCallId);
      if (part.type === "error" || part.type === "tool-error")
        errors.push(part.error);
    }
    expect(errors).toEqual([]);
    expect(results.sort()).toEqual([
      "contract_0",
      "contract_1",
      "contract_2",
      "contract_3",
    ]);
    expect(effect).toHaveBeenCalledTimes(3);
    await expect(agent.consume()).resolves.toEqual({ done: true });
  });

  it.each(
    [
      ["execute_command", "execute_command"],
      ["browser_navigate", "browser_snapshot"],
      ["create_file", "update_file"],
      ["update_file", "apply_patch"],
      ["apply_patch", "create_file"],
    ].flatMap(([first, second]) =>
      [true, false].map((nestedFirst) => ({ first, second, nestedFirst })),
    ),
  )("prevents overlapping $first / $second calls (nested first: $nestedFirst)", async ({
    first,
    second,
    nestedFirst,
  }) => {
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started = () => {};
    const ready = new Promise<void>((resolve) => {
      started = resolve;
    });
    const effect = vi.fn(async () => {
      if (effect.mock.calls.length === 1) {
        started();
        await held;
      }
      return "ok";
    });
    const names = [...new Set([first, second])];
    const { request } = makeAgent({
      activeTools: names,
      extraTools: Object.fromEntries(
        names.map((name) => [
          name,
          tool({
            inputSchema: z.object({}),
            execute: effect,
          }),
        ]),
      ),
      nestedTools: names,
    });
    let cell: CodeCellResult | undefined;
    let direct: Promise<unknown> | undefined;
    try {
      if (nestedFirst) {
        cell = await execute(request.tools, "exec", {
          code: `text(await tools.call(${JSON.stringify(first)}, {}))`,
          yield_time_ms: 0,
        });
        expect(cell.status).toBe("running");
      } else {
        direct = executeDirect(request.tools, first);
      }
      await ready;
      if (nestedFirst) {
        await expect(executeDirect(request.tools, second)).rejects.toThrow(
          "single-lane",
        );
      } else {
        const blocked = await execute(request.tools, "exec", {
          code: `await tools.call(${JSON.stringify(second)}, {})`,
        });
        expect(blocked.status).toBe("failed");
        expect(blocked.output).toContain("single-lane");
      }
      expect(effect).toHaveBeenCalledOnce();
    } finally {
      release();
      await direct;
      if (cell?.status === "running") {
        await execute(request.tools, "wait", { cell_id: cell.cellId });
      }
    }
    await expect(executeDirect(request.tools, second)).resolves.toBe("ok");
    expect(effect).toHaveBeenCalledTimes(2);
  });

  it.each([
    "terminate",
    "abort",
  ])("cancels a pending nested approval on %s", async (cancel) => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: undefined,
    });
    const effect = vi.fn(async () => "executed");
    const controller = new AbortController();
    let requested = () => {};
    const approvalReady = new Promise<void>((resolve) => {
      requested = resolve;
    });
    gate.once("approval-needed", requested);
    const { request } = makeAgent({
      activeTools: ["echo"],
      extraTools: {
        echo: tool({ inputSchema: z.object({}), execute: effect }),
      },
      nestedTools: ["echo"],
      approvalGate: gate,
    });
    try {
      const cell = await execute(
        request.tools,
        "exec",
        {
          code: 'await tools.call("echo", {})',
          yield_time_ms: 0,
        },
        {
          toolCallId: "awaiting_approval",
          messages: [],
          abortSignal: controller.signal,
        },
      );
      expect(cell.status).toBe("running");
      await approvalReady;
      const [approval] = gate.getPendingApprovals();
      expect(approval.toolCallId).toBe("awaiting_approval:nested:1");
      if (cancel === "abort") controller.abort("cancelled");
      const result = await execute(request.tools, "wait", {
        cell_id: cell.cellId,
        terminate: cancel === "terminate",
      });
      expect(result.status).toBe("terminated");
      expect(gate.getPendingApprovals()).toEqual([]);
      expect(effect).not.toHaveBeenCalled();
      expect(gate.getActionHistory()).toMatchObject([{ decision: "denied" }]);
      expect(() => gate.approve(approval.id)).toThrow("No pending approval");
    } finally {
      gate.denyAll();
    }
  });

  it("exposes only selected capabilities and keeps injected contracts direct by default", async () => {
    const echo = tool({
      inputSchema: z.strictObject({ value: z.number() }),
      execute: async ({ value }) => value * 2,
    });
    const submit = tool({
      inputSchema: z.object({ done: z.boolean() }),
      execute: async () => "done",
    });
    const { request } = makeAgent({
      activeTools: ["echo", "submit"],
      extraTools: { echo, submit, unavailable: echo },
      nestedTools: ["echo"],
    });
    expect(request.activeTools).toEqual(["exec", "wait", "echo", "submit"]);
    expect(request.tools.submit).toBe(submit);
    expect(request.tools.echo).toBe(echo);
    await expect(
      request.tools.echo.execute?.(
        { value: 21 },
        {
          toolCallId: "direct_echo",
          messages: [],
        },
      ),
    ).resolves.toBe(42);
    const result = await execute(request.tools, "exec", {
      code: 'text(ALL_TOOLS); text(await tools.call("echo", {value: 21})); try { await tools.call("unavailable", {value: 1}) } catch (e) { text(String(e)) }',
    });
    expect(result.status).toBe("completed");
    expect(result.output).toContain('["echo"]\n42');
    expect(result.output).toContain("Capability is not available");
    expect(request.system).toContain("Code execution interface");
  });

  it("uses existing approval behavior for both direct and nested calls", async () => {
    const bus = new AgentEventBus();
    const onResult = vi.fn();
    bus.on("tool-result", onResult);
    const gate = new ApprovalGate({ requireApproval: false });
    const check = vi.spyOn(gate, "check");
    const { request } = makeAgent({
      activeTools: ["echo"],
      extraTools: {
        echo: tool({
          inputSchema: z.strictObject({ value: z.number() }),
          execute: async ({ value }) => value,
        }),
      },
      nestedTools: ["echo"],
      eventBus: bus,
      approvalGate: gate,
      streamIdFactory: (event) =>
        event.kind === "tool-part" ? `part:${event.toolCallId}` : "message",
    });
    const result = await execute(request.tools, "exec", {
      code: 'text(await tools.call("echo", {value: 42}))',
    });
    expect(result.output).toBe("42");
    expect(check).toHaveBeenCalledWith("echo", "exec_test:nested:1", {
      value: 42,
    });
    expect(onResult).toHaveBeenCalledWith(
      expect.objectContaining({
        toolCallId: "exec_test:nested:1",
        partId: "part:exec_test:nested:1",
        result: 42,
      }),
    );
    await expect(
      request.tools.echo.execute?.(
        { value: 7 },
        {
          toolCallId: "direct_echo",
          messages: [],
        },
      ),
    ).resolves.toBe(7);
    expect(check).toHaveBeenCalledWith("echo", "direct_echo", { value: 7 });
    expect(check).toHaveBeenCalledTimes(2);
  });

  it.each([
    false,
    true,
  ])("disposes yielded cells when the stream ends (failure: %s)", async (failure) => {
    const completed = vi.fn();
    const { agent, request } = makeAgent({ onCodeCellComplete: completed });
    const initial = await execute(request.tools, "exec", {
      code: "await new Promise(() => {})",
      yield_time_ms: 5,
    });
    expect(initial.status).toBe("running");
    if (failure) observed.streamError = new Error("provider disconnected");
    if (failure)
      await expect(agent.consume()).rejects.toThrow("provider disconnected");
    else await agent.consume();
    expect(completed).toHaveBeenCalledWith(
      expect.objectContaining({ cellId: initial.cellId, status: "terminated" }),
    );
    await expect(
      execute(request.tools, "exec", { code: "text(1)" }),
    ).rejects.toThrow("disposed");
  });

  it("preserves the direct mode opt-out", () => {
    const echo = tool({ inputSchema: z.object({}), execute: async () => "ok" });
    const { request } = makeAgent({
      toolProtocol: "direct",
      activeTools: ["echo"],
      extraTools: { echo },
    });
    expect(request.activeTools).toEqual(["echo"]);
    expect(request.tools.echo).toBe(echo);
    expect(request.system).not.toContain("Code execution interface");
  });
});

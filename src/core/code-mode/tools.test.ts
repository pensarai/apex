import { type ToolSet, tool } from "ai";
import { describe, expect, test, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus } from "../eventBus";
import { CanonicalCapabilityInvoker } from "./capabilityInvoker";
import { CodeModeRuntime } from "./runtime";
import {
  buildCodeModeInstructions,
  createCodeModeTools,
  resolveCodeModeToolPresentation,
} from "./tools";

describe("workflow tool presentation", () => {
  test("exposes ordinary tools directly and through exec by default", () => {
    expect(
      resolveCodeModeToolPresentation({
        activeTools: [
          "response",
          "read_context",
          "execute_command",
          "read_file",
          "create_file",
          "http_request",
        ],
        extraTools: ["read_context"],
      }),
    ).toEqual({
      direct: [
        "response",
        "read_context",
        "execute_command",
        "read_file",
        "create_file",
        "http_request",
      ],
      nested: ["execute_command", "read_file", "create_file", "http_request"],
    });
  });

  test("explicit nested reads do not activate unavailable capabilities", () => {
    expect(
      resolveCodeModeToolPresentation({
        activeTools: ["response", "read_context"],
        extraTools: ["read_context", "unavailable"],
        nestedTools: ["read_context", "unavailable"],
      }),
    ).toEqual({
      direct: ["response", "read_context"],
      nested: ["read_context"],
    });
  });

  test("honors explicit direct-only capabilities", () => {
    expect(
      resolveCodeModeToolPresentation({
        activeTools: ["execute_command", "http_request"],
        directTools: ["execute_command"],
      }),
    ).toEqual({
      direct: ["execute_command", "http_request"],
      nested: ["http_request"],
    });
  });

  test("keeps explicitly nested reserved names off the direct surface", () => {
    expect(
      resolveCodeModeToolPresentation({
        activeTools: ["exec", "wait", "read_context"],
        extraTools: ["exec", "wait", "read_context"],
        nestedTools: ["exec", "wait", "read_context"],
      }),
    ).toEqual({
      direct: ["read_context"],
      nested: ["exec", "wait", "read_context"],
    });
  });

  test("cannot move lifecycle contracts or non-injected capabilities", () => {
    for (const name of ["response", "execute_command"]) {
      expect(() =>
        resolveCodeModeToolPresentation({
          activeTools: [name],
          extraTools: ["response"],
          nestedTools: [name],
        }),
      ).toThrow("Cannot present");
    }
  });
});

const runtime = {
  execute: async () => ({
    cellId: "cell_1",
    status: "completed",
    output: "ok",
  }),
  wait: async () => ({ cellId: "cell_1", status: "completed", output: "ok" }),
} as never;

const canonicalTools: ToolSet = {
  response: tool({ inputSchema: z.object({ result: z.string() }) }),
  document_vulnerability: tool({
    inputSchema: z.object({ title: z.string() }),
  }),
  checkpoint_state: tool({ inputSchema: z.object({ assessment: z.string() }) }),
  browser_screenshot: tool({ inputSchema: z.object({ filename: z.string() }) }),
  execute_command: tool({ inputSchema: z.object({ command: z.string() }) }),
};

describe("createCodeModeTools", () => {
  test.each([
    false,
    true,
  ])("cancels wait polling without terminating the cell (already aborted: %s)", async (alreadyAborted) => {
    const invoker = new CanonicalCapabilityInvoker({
      tools: {},
      allowedTools: [],
      eventBus: new AgentEventBus(),
      sessionId: "session_wait",
      getMessageId: () => "message_wait",
    });
    const cellRuntime = new CodeModeRuntime(invoker);
    const presented = createCodeModeTools("schema-code", cellRuntime, {}, []);
    const controller = new AbortController();
    const removeListener = vi.spyOn(controller.signal, "removeEventListener");
    try {
      const pending = await cellRuntime.execute(
        "await new Promise(() => {})",
        {
          parentToolCallId: "exec_pending",
          messages: [],
        },
        0,
      );
      expect(pending.status).toBe("running");
      const executeWait = presented.wait.execute;
      if (!executeWait) throw new Error("Missing wait executor");
      if (alreadyAborted) controller.abort(new Error("stop polling"));
      const result = executeWait(
        { cell_id: pending.cellId, yield_time_ms: 60_000 },
        {
          toolCallId: "wait_cancelled",
          messages: [],
          abortSignal: controller.signal,
        },
      );
      const rejected = expect(result).rejects.toThrow("stop polling");
      if (!alreadyAborted) controller.abort(new Error("stop polling"));
      await rejected;
      if (!alreadyAborted) {
        expect(removeListener).toHaveBeenCalledWith(
          "abort",
          expect.any(Function),
        );
      }
      expect(
        (await cellRuntime.wait(pending.cellId, { yieldTimeMs: 0 })).status,
      ).toBe("running");
      expect(
        (await cellRuntime.wait(pending.cellId, { terminate: true })).status,
      ).toBe("terminated");
    } finally {
      removeListener.mockRestore();
      await cellRuntime.dispose();
    }
  }, 2_000);

  test("rejects injected direct tools that collide with exec or wait", () => {
    expect(() =>
      createCodeModeTools(
        "schema-code",
        runtime,
        { exec: canonicalTools.response },
        ["exec"],
      ),
    ).toThrow("reserved by code mode");
  });
  test("native mode uses freeform exec and preserves Console contract tools", () => {
    const { direct } = resolveCodeModeToolPresentation({
      activeTools: Object.keys(canonicalTools),
    });
    const tools = createCodeModeTools(
      "native-code",
      runtime,
      canonicalTools,
      direct,
    );
    expect(Object.keys(tools)).toEqual([
      "exec",
      "wait",
      "response",
      "document_vulnerability",
      "checkpoint_state",
      "browser_screenshot",
      "execute_command",
    ]);
    expect(tools.exec.type).toBe("provider");
    expect(tools.execute_command).toBe(canonicalTools.execute_command);
  });

  test("schema mode preserves top-level Console contract tools", () => {
    const { direct } = resolveCodeModeToolPresentation({
      activeTools: Object.keys(canonicalTools),
    });
    const tools = createCodeModeTools(
      "schema-code",
      runtime,
      canonicalTools,
      direct,
    );
    expect(Object.keys(tools)).toEqual([
      "exec",
      "wait",
      "response",
      "document_vulnerability",
      "checkpoint_state",
      "browser_screenshot",
      "execute_command",
    ]);
    expect(tools.response).toBe(canonicalTools.response);
    expect(tools.execute_command).toBe(canonicalTools.execute_command);
  });

  test("instructions teach custom logic inside QuickJS cells", () => {
    const instructions = buildCodeModeInstructions("schema-code");
    expect(instructions).toContain("mapLimitSettled");
    expect(instructions).toContain("declare const ALL_TOOLS");
    expect(instructions).toContain("do not guess or probe capability names");
    expect(instructions).toContain("JavaScript directly in exec");
    expect(instructions).toContain(
      "Prefer exec for predictable tool orchestration",
    );
    expect(instructions).toContain("await each command sequentially");
    expect(instructions).toContain('tools.call("http_request"');
    expect(instructions).not.toContain("tools.shell");
    expect(instructions).not.toContain("python3 probe.py");
    expect(instructions).toContain("files persist in the session workspace");
    expect(instructions).toContain("exact nested toolCallId");
    expect(instructions).toContain("Guidance is process feedback");
    const tools = createCodeModeTools("schema-code", runtime, {}, []);
    expect(tools.exec.description).toContain("directly in the cell");
    expect(tools.exec.description).toContain("Use direct tools for standalone");
    expect(tools.exec.description).not.toContain("tools.shell");
  });

  test.each([
    1, 2,
  ])("documented coding cell %i executes with governed capabilities", async (index) => {
    const examples = [
      ...buildCodeModeInstructions("schema-code").matchAll(
        /```js\n([\s\S]*?)\n```/g,
      ),
    ];
    const example = examples[index]?.[1];
    if (!example) throw new Error("Missing documented coding cell");
    const writes: string[] = [];
    const capabilities = {
      read_file: tool({
        inputSchema: z.object({
          path: z.string(),
          toolCallDescription: z.string(),
        }),
        execute: async ({ path }) => ({
          success: true,
          content: path,
          truncated: false,
        }),
      }),
      create_file: tool({
        inputSchema: z.object({
          path: z.string(),
          content: z.string(),
          toolCallDescription: z.string(),
        }),
        execute: async ({ path }) => {
          await new Promise((resolve) => setTimeout(resolve, 1));
          writes.push(path);
          return { success: true, path };
        },
      }),
    };
    const invoker = new CanonicalCapabilityInvoker({
      tools: capabilities,
      allowedTools: Object.keys(capabilities),
      eventBus: new AgentEventBus(),
      sessionId: "session_coding_example",
      getMessageId: () => "message_coding_example",
    });
    const cellRuntime = new CodeModeRuntime(invoker, Object.keys(capabilities));
    try {
      const result = await cellRuntime.execute(example, {
        parentToolCallId: "exec_coding_example",
        messages: [],
      });
      expect(result.status).toBe("completed");
      if (index === 1) {
        expect(JSON.parse(result.output)).toEqual({
          paths: ["config/current.txt", "config/expected.txt"],
          identical: false,
        });
        expect(result.evidence?.map(({ toolName }) => toolName)).toEqual([
          "read_file",
          "read_file",
        ]);
      } else {
        expect(writes).toEqual([
          "scratchpad/input.txt",
          "scratchpad/expected.txt",
        ]);
        expect(result.evidence?.map(({ toolName }) => toolName)).toEqual([
          "create_file",
          "create_file",
        ]);
      }
    } finally {
      await cellRuntime.dispose();
    }
  });

  test("the documented HTTP cell composes requests and stores evidence without a shell", async () => {
    const instructions = buildCodeModeInstructions("schema-code");
    const example = instructions.match(/```js\n([\s\S]*?)\n```/)?.[1];
    if (!example)
      throw new Error("Instructions must include a JavaScript example");
    const requested: string[] = [];
    const capabilities = {
      http_request: tool({
        inputSchema: z.object({
          url: z.string(),
          method: z.literal("GET"),
          followRedirects: z.literal(false),
          toolCallDescription: z.string(),
        }),
        execute: async ({ url }) => {
          requested.push(url);
          return { status: 200, body: "x".repeat(600) };
        },
      }),
    };
    const invoker = new CanonicalCapabilityInvoker({
      tools: capabilities,
      allowedTools: Object.keys(capabilities),
      eventBus: new AgentEventBus(),
      sessionId: "session_example",
      getMessageId: () => "message_example",
    });
    const cellRuntime = new CodeModeRuntime(invoker, Object.keys(capabilities));
    try {
      const result = await cellRuntime.execute(example, {
        parentToolCallId: "exec_example",
        messages: [],
      });
      expect(result.status).toBe("completed");
      expect(requested).toEqual([
        "https://target.example/",
        "https://target.example/api/config",
      ]);
      expect(JSON.parse(result.output)).toEqual([
        { path: "/", status: 200, body: "x".repeat(500) },
        { path: "/api/config", status: 200, body: "x".repeat(500) },
      ]);
      expect(result.evidence?.map(({ toolName }) => toolName)).toEqual([
        "http_request",
        "http_request",
      ]);
      const stored = await cellRuntime.execute('text(load("observations"))', {
        parentToolCallId: "exec_stored",
        messages: [],
      });
      expect(stored.output).toBe(result.output);
    } finally {
      await cellRuntime.dispose();
    }
  });
});

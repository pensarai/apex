import { tool } from "ai";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus } from "../eventBus";
import { CanonicalCapabilityInvoker } from "./capabilityInvoker";

function createInvoker(
  execute = vi.fn(async ({ value }: { value: string }) => value),
) {
  const bus = new AgentEventBus();
  const tools = {
    example: tool({
      inputSchema: z.strictObject({ value: z.string() }),
      execute,
    }),
  };
  return {
    bus,
    execute,
    invoker: new CanonicalCapabilityInvoker({
      tools,
      allowedTools: ["example"],
      eventBus: bus,
      sessionId: "ses_test",
      getMessageId: () => "msg_test",
    }),
  };
}

describe("CanonicalCapabilityInvoker", () => {
  it("allows sibling contract tools to execute concurrently", async () => {
    let active = 0;
    let maxActive = 0;
    const execute = async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      return "ok";
    };
    const invoker = new CanonicalCapabilityInvoker({
      tools: {
        response: tool({
          inputSchema: z.object({ result: z.string() }),
          execute,
        }),
        document_vulnerability: tool({
          inputSchema: z.object({ title: z.string() }),
          execute,
        }),
      },
      allowedTools: [],
      eventBus: new AgentEventBus(),
      sessionId: "session",
      getMessageId: () => "message",
    });

    await Promise.all([
      invoker.tools.response.execute?.(
        { result: "done" },
        { toolCallId: "response", messages: [] },
      ),
      invoker.tools.document_vulnerability.execute?.(
        { title: "finding" },
        { toolCallId: "finding", messages: [] },
      ),
    ]);

    expect(maxActive).toBe(2);
  });

  it.each([
    "complete",
    "return",
    "throw",
  ])("holds the browser lane through streaming and releases it on %s", async (ending) => {
    const closed = vi.fn();
    const invoker = new CanonicalCapabilityInvoker({
      tools: {
        browser_navigate: tool({
          inputSchema: z.object({}),
          execute: async function* () {
            try {
              yield "working";
              if (ending === "throw") throw new Error("navigation failed");
              yield "done";
            } finally {
              closed();
            }
          },
        }),
        browser_snapshot: tool({
          inputSchema: z.object({}),
          execute: async () => "snapshot",
        }),
      },
      allowedTools: ["browser_snapshot"],
      eventBus: new AgentEventBus(),
      sessionId: "session",
      getMessageId: () => "message",
    });
    const stream = invoker.tools.browser_navigate.execute?.(
      {},
      { toolCallId: "direct", messages: [] },
    );
    if (
      !stream ||
      typeof stream !== "object" ||
      !(Symbol.asyncIterator in stream)
    ) {
      throw new Error("SDK must receive an async iterable directly");
    }
    const iterator = stream[Symbol.asyncIterator]();
    const snapshot = () =>
      invoker.invoke(
        "browser_snapshot",
        {},
        { parentToolCallId: "snapshot", messages: [] },
      );
    try {
      expect(await iterator.next()).toMatchObject({
        value: "working",
        done: false,
      });
      await expect(snapshot()).rejects.toThrow("single-lane");
      if (ending === "return") {
        await iterator.return?.();
      } else if (ending === "throw") {
        await expect(iterator.next()).rejects.toThrow("navigation failed");
      } else {
        expect(await iterator.next()).toMatchObject({
          value: "done",
          done: false,
        });
        await expect(snapshot()).rejects.toThrow("single-lane");
        expect(await iterator.next()).toMatchObject({ done: true });
      }
      expect(closed).toHaveBeenCalledOnce();
      await expect(snapshot()).resolves.toBe("snapshot");
    } finally {
      await iterator.return?.();
    }
  });

  it.each([
    "create_file",
    "update_file",
    "apply_patch",
  ])("does not recommend parallelizing %s writes", async (name) => {
    const invoker = new CanonicalCapabilityInvoker({
      tools: {
        [name]: tool({
          inputSchema: z.object({ value: z.number() }),
          execute: async () => "ok",
        }),
      },
      allowedTools: [name],
      eventBus: new AgentEventBus(),
      sessionId: "session",
      getMessageId: () => "message",
    });
    for (let value = 0; value < 4; value++) {
      await invoker.invoke(
        name,
        { value },
        { parentToolCallId: "writes", messages: [] },
      );
    }
    const result = invoker.completeCell("writes");
    expect(result.metrics).toMatchObject({
      nestedCalls: 4,
      uniqueCalls: 4,
      maxConcurrency: 1,
    });
    expect(result.guidance.join(" ")).not.toContain("mapLimit");
  });

  it("preserves execution context and uses the host ID factory for nested events", async () => {
    const execute = vi.fn(async () => "ok");
    const bus = new AgentEventBus();
    const onStart = vi.fn();
    bus.on("tool-call-start", onStart);
    const invoker = new CanonicalCapabilityInvoker({
      tools: {
        custom: tool({
          inputSchema: z.strictObject({ value: z.number() }),
          execute,
        }),
      },
      allowedTools: ["custom"],
      eventBus: bus,
      sessionId: "session",
      getMessageId: () => "message",
      getToolPartId: (id) => `part:${id}`,
    });
    const controller = new AbortController();
    const options = {
      parentToolCallId: "exec_2",
      messages: [],
      abortSignal: controller.signal,
      experimental_context: { tenant: "test" },
    };
    await invoker.invoke("custom", { value: 42 }, options);
    expect(execute).toHaveBeenCalledWith(
      { value: 42 },
      {
        toolCallId: "exec_2:nested:1",
        messages: [],
        abortSignal: controller.signal,
        experimental_context: options.experimental_context,
      },
    );
    expect(onStart).toHaveBeenCalledWith(
      expect.objectContaining({
        toolCallId: "exec_2:nested:1",
        partId: "part:exec_2:nested:1",
      }),
    );
    controller.abort(new Error("cancelled"));
    await expect(
      invoker.invoke("custom", { value: 42 }, options),
    ).rejects.toThrow("cancelled");
    expect(execute).toHaveBeenCalledOnce();
  });
  it("validates and executes canonical tools", async () => {
    const { invoker, execute } = createInvoker();
    await expect(
      invoker.invoke(
        "example",
        { value: "ok" },
        { parentToolCallId: "exec_1", messages: [] },
      ),
    ).resolves.toBe("ok");
    expect(execute).toHaveBeenCalledOnce();
  });

  it("adds a deterministic description for nested code-mode calls", async () => {
    const execute = vi.fn(
      async ({ toolCallDescription }: { toolCallDescription: string }) =>
        toolCallDescription,
    );
    const invoker = new CanonicalCapabilityInvoker({
      tools: {
        described: tool({
          inputSchema: z.object({ toolCallDescription: z.string().min(1) }),
          execute,
        }),
      },
      allowedTools: ["described"],
      eventBus: new AgentEventBus(),
      sessionId: "ses_test",
      getMessageId: () => "msg_test",
    });

    await expect(
      invoker.invoke(
        "described",
        {},
        { parentToolCallId: "exec_1", messages: [] },
      ),
    ).resolves.toBe("Invoke described from code mode");
  });

  it("emits the canonical tool lifecycle for Console", async () => {
    const { bus, invoker } = createInvoker();
    const events: string[] = [];
    bus.on("tool-call-start", (event) =>
      events.push(`start:${event.toolName}`),
    );
    bus.on("tool-call-complete", (event) =>
      events.push(`complete:${event.toolName}`),
    );
    bus.on("tool-result", (event) => events.push(`result:${event.toolName}`));

    await invoker.invoke(
      "example",
      { value: "ok" },
      { parentToolCallId: "exec_1", messages: [] },
    );

    expect(events).toEqual([
      "start:example",
      "complete:example",
      "result:example",
    ]);
  });

  it("describes an allowed nested capability without executing it", async () => {
    const { invoker, execute } = createInvoker();

    await expect(invoker.describe("example")).resolves.toMatchObject({
      name: "example",
      inputSchema: {
        type: "object",
        required: ["value"],
      },
    });
    expect(execute).not.toHaveBeenCalled();
    await expect(invoker.describe("other")).rejects.toThrow(
      "Capability is not available",
    );
  });

  it("rejects invalid and unavailable capability calls", async () => {
    const { invoker } = createInvoker();
    await expect(
      invoker.invoke(
        "example",
        { value: 1 },
        { parentToolCallId: "exec_1", messages: [] },
      ),
    ).rejects.toThrow("Invalid input for example");
    await expect(
      invoker.invoke("other", {}, { parentToolCallId: "exec_1", messages: [] }),
    ).rejects.toThrow("Capability is not available");
  });

  it("records nested concurrency and repeated calls per cell", async () => {
    let active = 0;
    let maxActive = 0;
    const { invoker } = createInvoker(
      vi.fn(async ({ value }: { value: string }) => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolve) => setTimeout(resolve, 5));
        active -= 1;
        return value;
      }),
    );

    await Promise.all([
      invoker.invoke(
        "example",
        { value: "a" },
        { parentToolCallId: "exec_parallel", messages: [] },
      ),
      invoker.invoke(
        "example",
        { value: "b" },
        { parentToolCallId: "exec_parallel", messages: [] },
      ),
      invoker.invoke(
        "example",
        { value: "a" },
        { parentToolCallId: "exec_parallel", messages: [] },
      ),
    ]);

    const observation = invoker.completeCell("exec_parallel");
    expect(maxActive).toBe(3);
    expect(observation.metrics).toEqual({
      nestedCalls: 3,
      uniqueCalls: 2,
      repeatedCalls: 1,
      maxConcurrency: 3,
    });
    expect(observation.evidence).toEqual([
      {
        toolCallId: "exec_parallel:nested:1",
        toolName: "example",
        status: "succeeded",
      },
      {
        toolCallId: "exec_parallel:nested:2",
        toolName: "example",
        status: "succeeded",
      },
      {
        toolCallId: "exec_parallel:nested:3",
        toolName: "example",
        status: "succeeded",
      },
    ]);
    expect(observation.guidance).toEqual([]);
  });

  it("warns after repeated one-call cells return no new result", async () => {
    const { invoker } = createInvoker();
    let guidance: string[] = [];

    for (let index = 0; index < 4; index += 1) {
      const parentToolCallId = `exec_${index}`;
      await invoker.invoke(
        "example",
        { value: "same" },
        { parentToolCallId, messages: [] },
      );
      guidance = invoker.completeCell(parentToolCallId).guidance;
    }

    expect(guidance.join(" ")).toContain("one-call exec cells");
    expect(guidance.join(" ")).toContain("same result");
  });

  it("directs shell batches toward JavaScript cells and provided capabilities", async () => {
    const bus = new AgentEventBus();
    const invoker = new CanonicalCapabilityInvoker({
      tools: {
        execute_command: tool({
          inputSchema: z.object({ command: z.string() }),
          execute: async ({ command }) => command,
        }),
      },
      allowedTools: ["execute_command"],
      eventBus: bus,
      sessionId: "ses_test",
      getMessageId: () => "msg_test",
    });

    for (const command of ["one", "two", "three", "four"]) {
      await invoker.invoke(
        "execute_command",
        { command },
        { parentToolCallId: "exec_shell", messages: [] },
      );
    }

    const guidance = invoker.completeCell("exec_shell").guidance.join(" ");
    expect(guidance).toContain("JavaScript inside exec");
    expect(guidance).toContain("await each command sequentially");
    expect(guidance).not.toContain("one reusable script");
    expect(guidance).not.toContain("combine them with mapLimit");
  });
});

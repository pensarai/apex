import { type ToolSet, tool } from "ai";
import { describe, expect, test, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus } from "../../../eventBus";
import { CanonicalCapabilityInvoker } from "./capabilityInvoker";
import { CodeModeRuntime } from "./runtime";

function createRuntime(tools: ToolSet) {
  const invoker = new CanonicalCapabilityInvoker({
    tools,
    allowedTools: Object.keys(tools),
    eventBus: new AgentEventBus(),
    sessionId: "session_test",
    getMessageId: () => "message_test",
  });
  return new CodeModeRuntime(invoker);
}

const context = {
  parentToolCallId: "exec_1",
  messages: [],
};

describe("CodeModeRuntime", () => {
  test("composes nested calls and returns selected output", async () => {
    const runtime = createRuntime({
      double: tool({
        inputSchema: z.object({ value: z.number() }),
        execute: async ({ value }) => ({ value: value * 2 }),
      }),
    });

    const result = await runtime.execute(
      `
        const values = await Promise.all([
          tools.call("double", { value: 2 }),
          tools.call("double", { value: 4 }),
        ]);
        text(values.map(item => item.value));
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("completed");
    expect(result.output).toBe("[4,8]");
    expect(result.evidence).toEqual([
      {
        toolCallId: "exec_1:nested:1",
        toolName: "double",
        status: "succeeded",
      },
      {
        toolCallId: "exec_1:nested:2",
        toolName: "double",
        status: "succeeded",
      },
    ]);
    await runtime.dispose();
  });

  test("mapLimit bounds nested capability concurrency", async () => {
    let active = 0;
    let maxActive = 0;
    const runtime = createRuntime({
      inspect: tool({
        inputSchema: z.object({ value: z.number() }),
        execute: async ({ value }) => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          await new Promise((resolve) => setTimeout(resolve, 5));
          active -= 1;
          return value * 2;
        },
      }),
    });

    const result = await runtime.execute(
      `
        const values = await mapLimit([1, 2, 3, 4, 5, 6], 2, value =>
          tools.call("inspect", { value })
        );
        text(values);
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("completed");
    expect(result.output).toBe("[2,4,6,8,10,12]");
    expect(maxActive).toBe(2);
    expect(result.metrics).toMatchObject({
      nestedCalls: 6,
      uniqueCalls: 6,
      maxConcurrency: 2,
    });
    await runtime.dispose();
  });

  test("rejects oversized stored host-call results without leaking the runtime", async () => {
    const payload = "x".repeat(100_000);
    const runtime = createRuntime({
      read_chunk: tool({
        inputSchema: z.object({ index: z.number() }),
        execute: async ({ index }) => ({ index, payload }),
      }),
    });

    const result = await runtime.execute(
      `
        const chunks = await mapLimit(
          Array.from({ length: 48 }, (_, index) => index),
          4,
          index => tools.call("read_chunk", { index }),
        );
        store("large-results", chunks);
        text(chunks.map(({ index, payload }) => ({ index, length: payload.length })));
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("failed");
    expect(result.output).toContain("split large reads across cells");
    expect(result.metrics?.nestedCalls).toBeLessThan(48);
    await runtime.dispose();
  });

  test("rejects loading oversized cumulative stored state without leaking the runtime", async () => {
    const runtime = createRuntime({});
    for (let index = 0; index < 4; index += 1) {
      const stored = await runtime.execute(
        `store("part-${index}", "x".repeat(400_000));`,
        { ...context, parentToolCallId: `store_${index}` },
        5_000,
      );
      expect(stored.status).toBe("completed");
    }

    const result = await runtime.execute(
      `text([load("part-0"), load("part-1"), load("part-2"), load("part-3")].length);`,
      { ...context, parentToolCallId: "load_all" },
      5_000,
    );

    expect(result.status).toBe("failed");
    expect(result.output).toContain("load compact state");
    await runtime.dispose();
  });

  test("rejects overlapping calls to the single-lane shell", async () => {
    let calls = 0;
    const runtime = createRuntime({
      execute_command: tool({
        inputSchema: z.object({ command: z.string() }),
        execute: async () => {
          calls += 1;
          await new Promise((resolve) => setTimeout(resolve, 20));
          return { stdout: "ok" };
        },
      }),
    });

    const result = await runtime.execute(
      `
        const results = await Promise.allSettled([
          tools.shell({ command: "first" }),
          tools.call("execute_command", { command: "second" }),
        ]);
        text(results);
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("completed");
    expect(result.output).toContain("tools.shell is single-lane");
    expect(calls).toBe(1);
    await runtime.dispose();
  });

  test("rejects overlapping shell calls across concurrent exec cells", async () => {
    let active = 0;
    let maxActive = 0;
    const runtime = createRuntime({
      execute_command: tool({
        inputSchema: z.object({ command: z.string() }),
        execute: async () => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          await new Promise((resolve) => setTimeout(resolve, 30));
          active -= 1;
          return { stdout: "ok" };
        },
      }),
    });

    const [first, second] = await Promise.all([
      runtime.execute(
        `text(await tools.shell({ command: "first" }));`,
        context,
        5_000,
      ),
      runtime.execute(
        `text(await tools.shell({ command: "second" }));`,
        { ...context, parentToolCallId: "exec_2" },
        5_000,
      ),
    ]);

    expect([first.status, second.status].sort()).toEqual([
      "completed",
      "failed",
    ]);
    expect(`${first.output}\n${second.output}`).toContain(
      "single-lane across exec cells",
    );
    expect(maxActive).toBe(1);
    await runtime.dispose();
  });

  test("keeps the VM alive until an in-flight host call settles after Promise.all rejects", async () => {
    let firstCompleted = false;
    const runtime = createRuntime({
      execute_command: tool({
        inputSchema: z.object({ command: z.string() }),
        execute: async () => {
          await new Promise((resolve) => setTimeout(resolve, 30));
          firstCompleted = true;
          return { stdout: "ok" };
        },
      }),
    });

    const result = await runtime.execute(
      `
        await Promise.all([
          tools.shell({ command: "first" }),
          tools.shell({ command: "second" }),
        ]);
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("failed");
    expect(result.output).toContain("tools.shell is single-lane");
    expect(firstCompleted).toBe(true);
    await runtime.dispose();
  });

  test("bounds shell calls by default without overriding explicit timeouts", async () => {
    const timeouts: Array<number | undefined> = [];
    const runtime = createRuntime({
      execute_command: tool({
        inputSchema: z.object({
          command: z.string(),
          timeout: z.number().optional(),
        }),
        execute: async ({ timeout }) => {
          timeouts.push(timeout);
          return { stdout: "ok" };
        },
      }),
    });

    const result = await runtime.execute(
      `
        await tools.shell({ command: "default" });
        await tools.shell({ command: "explicit", timeout: 300 });
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("completed");
    expect(timeouts).toEqual([120, 300]);
    await runtime.dispose();
  });

  test("shares one lane across browser operations", async () => {
    let calls = 0;
    const browserTool = tool({
      inputSchema: z.object({}),
      execute: async () => {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return { ok: true };
      },
    });
    const runtime = createRuntime({
      browser_navigate: browserTool,
      browser_snapshot: browserTool,
    });

    const result = await runtime.execute(
      `
        const results = await Promise.allSettled([
          tools.browser.navigate({}),
          tools.browser.snapshot({}),
        ]);
        text(results);
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("completed");
    expect(result.output).toContain("Browser operations are single-lane");
    expect(calls).toBe(1);
    await runtime.dispose();
  });

  test("persists explicitly stored values without exposing host globals", async () => {
    const runtime = createRuntime({});
    const first = await runtime.execute(
      `
        store("token", { value: 42 });
        text(typeof process);
        text(typeof fetch);
      `,
      context,
      5_000,
    );
    const second = await runtime.execute(
      `text(load("token"));`,
      { ...context, parentToolCallId: "exec_2" },
      5_000,
    );

    expect(first.output).toBe("undefined\nundefined");
    expect(second.output).toBe('{"value":42}');
    await runtime.dispose();
  });

  test("provides bounded base64, Buffer, require, and timer compatibility", async () => {
    const runtime = createRuntime({});
    const result = await runtime.execute(
      `
        const { Buffer: RequiredBuffer } = require("buffer");
        text(Buffer.from("hello").toString("base64"));
        text(RequiredBuffer.from("aGVsbG8=", "base64").toString("utf8"));
        text(btoa("Apex"));
        text(atob("QXBleA=="));
        await new Promise((resolve) => setTimeout(resolve, 5));
        await require("timers/promises").setTimeout(5);
        text("timer-complete");
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("completed");
    expect(result.output).toBe(
      "aGVsbG8=\nhello\nQXBleA==\nApex\ntimer-complete",
    );
    await runtime.dispose();
  });

  test("prevents capability calls after terminal response", async () => {
    const runtime = createRuntime({
      response: tool({
        inputSchema: z.object({ result: z.object({ solved: z.boolean() }) }),
        execute: async () => ({ success: true }),
      }),
      execute_command: tool({
        inputSchema: z.object({ command: z.string() }),
        execute: async () => ({ stdout: "unexpected" }),
      }),
    });

    const result = await runtime.execute(
      `
        await tools.call("response", { result: { solved: true } });
        await tools.call("execute_command", { command: "id" });
      `,
      context,
      5_000,
    );

    expect(result.status).toBe("failed");
    expect(result.output).toContain("response has already been submitted");
    await runtime.dispose();
  });

  test("interrupts unbounded guest CPU work", async () => {
    const runtime = createRuntime({});
    const startedAt = Date.now();
    const result = await runtime.execute("while (true) {}", context, 5_000);

    expect(result.status).toBe("failed");
    expect(Date.now() - startedAt).toBeLessThan(3_500);
    await runtime.dispose();
  }, 5_000);

  test("releases bridge resources across repeated sequential async cells", async () => {
    const runtime = createRuntime({
      read_chunk: tool({
        inputSchema: z.object({ index: z.number() }),
        execute: async ({ index }) => ({
          content: JSON.stringify({ index, value: "x".repeat(2_000) }),
        }),
      }),
    });

    for (let round = 0; round < 20; round++) {
      const result = await runtime.execute(
        `
          const chunks = [];
          for (let index = 0; index < 30; index++) {
            const result = await tools.call("read_chunk", { index });
            chunks.push(JSON.parse(result.content));
          }
          store("manifest", chunks);
          text(chunks.length);
        `,
        { ...context, parentToolCallId: `exec_${round}` },
        5_000,
      );

      expect(result.status).toBe("completed");
      expect(result.output).toBe("30");
      expect(result.metrics?.nestedCalls).toBe(30);
    }

    await runtime.dispose();
  });

  test("exposes nested capability schemas without executing them", async () => {
    const execute = vi.fn(async () => "executed");
    const runtime = createRuntime({
      schema_example: tool({
        inputSchema: z.object({ targetId: z.string() }),
        execute,
      }),
    });

    const result = await runtime.execute(
      `const schema = await tools.describe("schema_example"); text(schema.inputSchema.required);`,
      context,
      5_000,
    );

    expect(result.status).toBe("completed");
    expect(result.output).toContain("targetId");
    expect(execute).not.toHaveBeenCalled();
    await runtime.dispose();
  });

  test("aborts a guest sleep without waiting for its timer", async () => {
    const runtime = createRuntime({});
    const controller = new AbortController();
    const initial = await runtime.execute(
      `await sleep(30_000);`,
      { ...context, abortSignal: controller.signal },
      25,
    );

    expect(initial.status).toBe("running");
    const startedAt = Date.now();
    controller.abort("test abort");
    const result = await runtime.wait(initial.cellId, { yieldTimeMs: 2_000 });

    expect(result.status).toBe("terminated");
    expect(Date.now() - startedAt).toBeLessThan(1_000);
    await runtime.dispose();
  });

  test("aborts a host bridge even when the host operation does not settle", async () => {
    const runtime = createRuntime({
      never_returns: tool({
        inputSchema: z.object({}),
        execute: async () => new Promise(() => {}),
      }),
    });
    const controller = new AbortController();
    const initial = await runtime.execute(
      `await tools.call("never_returns", {});`,
      { ...context, abortSignal: controller.signal },
      25,
    );

    expect(initial.status).toBe("running");
    controller.abort("test abort");
    const result = await runtime.wait(initial.cellId, { yieldTimeMs: 2_000 });

    expect(result.status).toBe("terminated");
    await runtime.dispose();
  });

  test("dispose is idempotent and rejects new cells", async () => {
    const runtime = createRuntime({});

    await Promise.all([
      runtime.dispose(),
      runtime.dispose(),
      runtime.dispose(),
    ]);
    await runtime.dispose();

    await expect(runtime.execute(`text("late");`, context)).rejects.toThrow(
      "Code-mode runtime is disposed",
    );
  });
});

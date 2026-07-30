import { type ToolSet, tool } from "ai";
import { describe, expect, test } from "vitest";
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
});

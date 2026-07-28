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
        await tools.response.submit({ solved: true });
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

import { tool } from "ai";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus } from "../../../eventBus";
import { CanonicalCapabilityInvoker } from "./capabilityInvoker";

function createInvoker(
  execute = vi.fn(async ({ value }: { value: string }) => value),
) {
  const bus = new AgentEventBus();
  const tools = {
    example: tool({
      inputSchema: z.object({ value: z.string() }),
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
});

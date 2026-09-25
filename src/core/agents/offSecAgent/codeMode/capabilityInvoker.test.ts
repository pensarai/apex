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
});

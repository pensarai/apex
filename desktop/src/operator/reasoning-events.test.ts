import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentEventBus } from "../../../src/core/eventBus";
import { convertModelMessagesToUI } from "../../../src/core/session/persistence";
import type { DisplayMessage } from "../../../src/tui/components/agent-display";
import { appendStreamedText } from "../../../src/tui/components/operator-dashboard/display-state";
import { bindReasoningEvents, finishReasoning } from "./reasoning-events";

function fixture() {
  const bus = new AgentEventBus();
  const transcripts = new Map<string, DisplayMessage[]>();
  let current = true;
  const resetText = vi.fn();
  const unbind = bindReasoningEvents(bus, {
    isCurrent: () => current,
    resetText,
    update: (agent, updater) => {
      const key = agent ?? "root";
      transcripts.set(key, updater(transcripts.get(key) ?? []));
    },
  });
  return {
    bus,
    transcripts,
    resetText,
    unbind,
    messages: (agent = "root") => transcripts.get(agent) ?? [],
    expire: () => {
      current = false;
    },
  };
}

afterEach(() => vi.restoreAllMocks());

describe("desktop reasoning", () => {
  it("streams text and measured duration without replacing the answer", () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1000);
    const { bus, messages, resetText } = fixture();
    bus.emit("reasoning-start", {});
    const started = messages()[0];
    bus.emit("reasoning-delta", { text: "Check " });
    bus.emit("reasoning-delta", { text: "the boundary." });
    expect(messages()[0].createdAt).toBe(started.createdAt);
    expect(started.reasoning?.text).toBe("");
    now.mockReturnValue(13000);
    bus.emit("reasoning-end", {});
    const result = appendStreamedText(messages(), "Here is the result.");
    expect(result[0]).toMatchObject({
      content: "Here is the result.",
      reasoning: {
        text: "Check the boundary.",
        startedAt: 1000,
        endedAt: 13000,
        complete: true,
      },
    });
    expect(resetText).toHaveBeenCalledOnce();
  });

  it("keeps concurrent child reasoning separate from root and sibling blocks", () => {
    const { bus, messages, resetText } = fixture();
    for (const subagentId of [undefined, "a", "b"]) {
      bus.emit("reasoning-start", { subagentId });
      bus.emit("reasoning-delta", { subagentId, text: subagentId ?? "root" });
    }
    bus.emit("subagent-complete", { subagentId: "a", status: "completed" });
    expect(messages("a")[0].reasoning).toMatchObject({
      text: "a",
      complete: true,
    });
    expect(messages("b")[0].reasoning).toMatchObject({
      text: "b",
      complete: false,
    });
    expect(messages()[0].reasoning).toMatchObject({
      text: "root",
      complete: false,
    });
    expect(resetText).toHaveBeenCalledOnce();
  });

  it("handles missing boundaries and settles interrupted reasoning", () => {
    const { bus, messages } = fixture();
    bus.emit("reasoning-delta", { text: "First block" });
    bus.emit("text-delta", { text: "Answer" });
    expect(messages()[0].reasoning?.complete).toBe(true);
    bus.emit("reasoning-start", {});
    bus.emit("reasoning-delta", { text: "Second block" });
    const settled = finishReasoning(messages(), 42000);
    expect(settled).toHaveLength(2);
    expect(settled[1].reasoning).toMatchObject({
      text: "Second block",
      complete: true,
      endedAt: 42000,
    });
    expect(finishReasoning(settled)).toBe(settled);
  });

  it("stops accepting events after generation expiry and releases listeners", () => {
    const { bus, messages, expire, unbind } = fixture();
    const off = vi.spyOn(bus, "off");
    bus.emit("reasoning-start", {});
    expire();
    bus.emit("reasoning-delta", { text: "Stale output" });
    expect(messages()[0].reasoning?.text).toBe("");
    unbind();
    unbind();
    expect(off).toHaveBeenCalledTimes(7);
  });

  it("restores saved reasoning in order without fabricating timing or changing TUI output", () => {
    const saved = [
      {
        role: "assistant" as const,
        content: [
          { type: "reasoning" as const, text: "Inspect the routes." },
          { type: "text" as const, text: "The routes are scoped." },
          {
            type: "reasoning" as const,
            text: "Check the authentication boundary.",
          },
        ],
      },
    ];
    const restored = convertModelMessagesToUI(saved, true);
    expect(
      restored.map((message) => message.reasoning?.text ?? message.content),
    ).toEqual([
      "Inspect the routes.",
      "The routes are scoped.",
      "Check the authentication boundary.",
    ]);
    expect(restored[0].reasoning).toEqual({
      text: "Inspect the routes.",
      complete: true,
    });
    expect(convertModelMessagesToUI(saved)).toHaveLength(1);
  });
});

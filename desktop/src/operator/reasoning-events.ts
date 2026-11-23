import type { AgentEventBus, AgentEventMap } from "../../../src/core/eventBus";
import type { DisplayMessage } from "../../../src/tui/components/agent-display";

export function finishReasoning(messages: DisplayMessage[], now = Date.now()) {
  if (
    !messages.some(
      (message) => message.reasoning && !message.reasoning.complete,
    )
  )
    return messages;
  return messages.map((message) =>
    message.reasoning && !message.reasoning.complete
      ? {
          ...message,
          reasoning: { ...message.reasoning, complete: true, endedAt: now },
        }
      : message,
  );
}

export function bindReasoningEvents(
  bus: AgentEventBus,
  options: {
    isCurrent: () => boolean;
    resetText: () => void;
    update: (
      agentId: string | undefined,
      updater: (messages: DisplayMessage[]) => DisplayMessage[],
    ) => void;
  },
) {
  const removers: (() => void)[] = [];
  const bind = <K extends keyof AgentEventMap>(
    event: K,
    handler: (payload: AgentEventMap[K]) => void,
  ) => {
    const listener = (payload: AgentEventMap[K]) => {
      if (options.isCurrent()) handler(payload);
    };
    bus.on(event, listener);
    removers.push(() => bus.off(event, listener));
  };
  const start = (agentId: string | undefined, text = "") => {
    if (!agentId) options.resetText();
    options.update(agentId, (messages) => [
      ...finishReasoning(messages),
      {
        role: "assistant",
        content: "",
        createdAt: new Date(),
        reasoning: { text, startedAt: Date.now(), complete: false },
      },
    ]);
  };
  const end = ({ subagentId }: { subagentId?: string }) =>
    options.update(subagentId, finishReasoning);

  bind("reasoning-start", ({ subagentId }) => start(subagentId));
  bind("reasoning-delta", ({ subagentId, text }) => {
    let found = false;
    options.update(subagentId, (messages) => {
      const index = messages.findLastIndex(
        (message) => message.reasoning && !message.reasoning.complete,
      );
      if (index < 0) return messages;
      const message = messages[index];
      const reasoning = message.reasoning;
      if (!reasoning) return messages;
      found = true;
      const next = [...messages];
      next[index] = {
        ...message,
        reasoning: { ...reasoning, text: reasoning.text + text },
      };
      return next;
    });
    if (!found) start(subagentId, text);
  });
  bind("reasoning-end", end);
  bind("text-delta", end);
  bind("tool-call-start", end);
  bind("tool-call-complete", end);
  bind("subagent-complete", end);
  return () => {
    for (const remove of removers.splice(0)) remove();
  };
}

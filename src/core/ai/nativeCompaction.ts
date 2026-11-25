import type { ModelMessage } from "ai";
import { getModelInfo } from "./models";

export function supportsNativeCompaction(model: string): boolean {
  return (
    getModelInfo(model).provider === "openai" &&
    /^gpt-(?:6(?:[.-]|$)|5\.[3-9](?:[.-]|$))/.test(model)
  );
}

/** Only server-emitted compaction items authorize dropping their preceding window. */
export function nativeCompactionWindow(
  messages: ModelMessage[],
): ModelMessage[] {
  for (let index = messages.length - 1; index >= 0; index--) {
    const message = messages[index]!;
    if (message.role !== "assistant" || !Array.isArray(message.content))
      continue;
    const partIndex = message.content.findLastIndex(
      (part) =>
        part.type === "custom" &&
        part.kind === "openai.compaction" &&
        typeof part.providerOptions?.openai?.encryptedContent === "string" &&
        typeof part.providerOptions?.openai?.itemId === "string",
    );
    if (partIndex < 0) continue;
    const window: ModelMessage[] = [
      { ...message, content: message.content.slice(partIndex) },
      ...messages.slice(index + 1),
    ];
    // Explicit compaction requires restating positioned settings after the marker.
    const update = messages
      .slice(0, index + 1)
      .findLast(
        (m) =>
          m.role === "system" &&
          m.providerOptions?.openai?.reasoningEffortUpdate !== undefined,
      );
    if (
      update &&
      !window.some(
        (m) =>
          m.role === "system" &&
          m.providerOptions?.openai?.reasoningEffortUpdate !== undefined,
      )
    ) {
      const nextUser = window.findIndex((message) => message.role === "user");
      window.splice(nextUser < 0 ? window.length : nextUser, 0, update);
    }
    return window;
  }
  return messages;
}

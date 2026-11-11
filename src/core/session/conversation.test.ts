import type { ModelMessage } from "ai";
import { describe, expect, it } from "vitest";
import { prepareConversationMessages } from "./index";

describe("preserved conversation history", () => {
  it("retains early hints, adjacent user attachments, and opaque reasoning across resume", () => {
    const messages: ModelMessage[] = [
      {
        role: "user",
        content: "Investigate request boundaries; do not scan other hosts.",
      },
      ...Array.from(
        { length: 80 },
        (_, i): ModelMessage => ({
          role: i % 2 === 0 ? "assistant" : "user",
          content: `turn ${i}`,
        }),
      ),
      {
        role: "user",
        content: [
          { type: "text", text: "Check the parser discrepancy first." },
        ],
      },
      {
        role: "user",
        content: [
          {
            type: "file",
            data: "dGVzdA==",
            mediaType: "text/plain",
            filename: "capture.txt",
          },
        ],
      },
      {
        role: "assistant",
        content: [
          {
            type: "reasoning",
            text: "",
            providerOptions: {
              openai: { itemId: "rs_1", reasoningEncryptedContent: "opaque" },
            },
          },
        ],
      },
    ];
    const original = structuredClone(messages);
    const restored = prepareConversationMessages(messages, {
      preserveHistory: true,
      resume: true,
    });
    expect(restored).toBe(messages);
    expect(restored).toEqual(original);
    const continued = prepareConversationMessages(
      [...restored, { role: "user", content: "Continue with that evidence." }],
      { preserveHistory: true },
    );
    expect(continued.slice(0, -1)).toEqual(original);
    expect(
      prepareConversationMessages(messages, { resume: true }).length,
    ).toBeLessThan(messages.length);
  });

  it("repairs legacy tool outputs without rewriting surrounding user messages", () => {
    const messages = [
      { role: "user", content: "Keep this hint." },
      {
        role: "user",
        content: [{ type: "text", text: "And this correction." }],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "call_1",
            toolName: "read",
            output: "legacy",
          },
        ],
      },
    ] as unknown as ModelMessage[];
    const restored = prepareConversationMessages(messages, {
      preserveHistory: true,
    });
    expect(restored.slice(0, 2)).toEqual(messages.slice(0, 2));
    expect(restored[2]).toMatchObject({
      content: [{ output: { type: "text", value: "legacy" } }],
    });
    expect(messages[2]).toMatchObject({ content: [{ output: "legacy" }] });
  });
});

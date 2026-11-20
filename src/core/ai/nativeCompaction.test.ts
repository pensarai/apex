import type { ModelMessage } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { streamResponse } from "./ai";
import {
  nativeCompactionWindow,
  supportsNativeCompaction,
} from "./nativeCompaction";

const opaque: ModelMessage = {
  role: "assistant",
  content: [
    {
      type: "custom",
      kind: "openai.compaction",
      providerOptions: {
        openai: {
          type: "compaction",
          itemId: "cmp_1",
          encryptedContent: "encrypted-state",
        },
      },
    },
  ],
};
afterEach(() => vi.unstubAllGlobals());

describe("native research compaction", () => {
  it("retains the opaque item, ordered suffix, and positioned settings", () => {
    const update: ModelMessage = {
      role: "system",
      content: "",
      providerOptions: { openai: { reasoningEffortUpdate: "high" } },
    };
    const result: ModelMessage = {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolName: "read",
          toolCallId: "tc",
          output: { type: "text", value: "source evidence" },
        },
      ],
    };
    const call: ModelMessage = {
      role: "assistant",
      content: [
        { type: "tool-call", toolCallId: "tc", toolName: "read", input: {} },
      ],
    };
    expect(
      nativeCompactionWindow([
        { role: "user", content: "old" },
        update,
        opaque,
        call,
        result,
      ]),
    ).toEqual([opaque, call, result, update]);
  });

  it("restates an effort update before the next user message after compaction", () => {
    const update: ModelMessage = {
      role: "system",
      content: "",
      providerOptions: { openai: { reasoningEffortUpdate: "high" } },
    };
    const user: ModelMessage = { role: "user", content: "Follow the new hint" };
    expect(nativeCompactionWindow([update, opaque, user])).toEqual([
      opaque,
      update,
      user,
    ]);
  });

  it("does not claim native support through gateways or change ordinary history", () => {
    expect(supportsNativeCompaction("gpt-6.1-sol")).toBe(true);
    expect(supportsNativeCompaction("openai/gpt-6.1-sol")).toBe(false);
    expect(supportsNativeCompaction("claude-opus-5-5")).toBe(false);
    const history: ModelMessage[] = [{ role: "user", content: "hint" }];
    expect(nativeCompactionWindow(history)).toBe(history);
  });

  it("round-trips real SDK custom output through persistence and the Responses wire format", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: unknown, init?: RequestInit) => {
        bodies.push(JSON.parse(String(init?.body)));
        const chunks = [
          {
            type: "response.created",
            response: { id: "resp_1", created_at: 1, model: "gpt-6.1-sol" },
          },
          {
            type: "response.output_item.done",
            output_index: 0,
            item: {
              type: "compaction",
              id: "cmp_1",
              encrypted_content: "encrypted-state",
            },
          },
          {
            type: "response.completed",
            response: { usage: { input_tokens: 100, output_tokens: 10 } },
          },
        ];
        return new Response(
          chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join(""),
          { headers: { "content-type": "text/event-stream" } },
        );
      }),
    );
    const opts = {
      model: "gpt-6.1-sol",
      prompt: "investigate",
      reasoning: "low" as const,
      nativeCompaction: true,
      preserveHistory: true,
      authConfig: { openAiAPIKey: "test" },
      silent: true,
    };
    const first = streamResponse({
      ...opts,
      messages: [{ role: "user", content: "x".repeat(4_200_000) }],
    });
    for await (const _chunk of first.fullStream) {
      /* drain the provider stream */
    }
    const persisted = JSON.parse(
      JSON.stringify((await first.response).messages),
    ) as ModelMessage[];
    expect(persisted).toEqual([opaque]);
    const next = streamResponse({
      ...opts,
      messages: [
        ...persisted,
        {
          role: "system",
          content: "",
          providerOptions: { openai: { reasoningEffortUpdate: "high" } },
        },
        { role: "user", content: "Follow this hint" },
      ],
    });
    for await (const _chunk of next.fullStream) {
      /* drain the provider stream */
    }
    expect(bodies).toHaveLength(2);
    expect(bodies[0]?.input).toEqual(
      expect.arrayContaining([{ type: "compaction_trigger" }]),
    );
    expect(bodies[1]).toMatchObject({
      store: false,
      reasoning: { effort: "low" },
      input: [
        {
          type: "compaction",
          id: "cmp_1",
          encrypted_content: "encrypted-state",
        },
        { type: "configuration_update", reasoning: { effort: "high" } },
        {
          role: "user",
          content: [{ type: "input_text", text: "Follow this hint" }],
        },
      ],
    });
    expect(bodies[1]).not.toHaveProperty("context_management");
    const older = streamResponse({ ...opts, model: "gpt-5.3-codex" });
    for await (const _chunk of older.fullStream) {
      /* drain */
    }
    expect(bodies[2]?.context_management).toEqual([
      { type: "compaction", compact_threshold: expect.any(Number) },
    ]);
  });
});

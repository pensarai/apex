import type { ModelMessage } from "ai";
import { describe, expect, it } from "vitest";
import {
  buildMissingResponseContinuationMessages,
  buildOutputLimitContinuationMessages,
  shouldResumeMissingResponse,
} from "./ai";

describe("provider-turn continuation", () => {
  it("keeps completed prose but drops a truncated tool call", () => {
    const base: ModelMessage[] = [{ role: "user", content: "Test target" }];
    const response = [
      {
        role: "assistant",
        content: [
          { type: "reasoning", text: "The exploit is almost ready." },
          { type: "text", text: "I will run it now." },
          {
            type: "tool-call",
            toolCallId: "truncated",
            toolName: "exec",
            input: '{"code":"unfinished',
          },
        ],
      },
    ] as ModelMessage[];

    const continued = buildOutputLimitContinuationMessages(base, response);
    expect(continued[1]).toEqual({
      role: "assistant",
      content: [
        { type: "reasoning", text: "The exploit is almost ready." },
        { type: "text", text: "I will run it now." },
      ],
    });
    expect(continued.at(-1)).toMatchObject({
      role: "user",
      content: expect.stringContaining("output-token limit"),
    });
  });

  it("preserves a completed turn before requiring the response tool", () => {
    const base: ModelMessage[] = [{ role: "user", content: "Recover result" }];
    const response: ModelMessage[] = [
      { role: "assistant", content: "The evidence is sufficient." },
    ];

    const continued = buildMissingResponseContinuationMessages(base, response);
    expect(continued[1]).toEqual(response[0]);
    expect(continued.at(-1)).toMatchObject({
      role: "user",
      content: expect.stringContaining('required "response" completion tool'),
    });
  });

  it("resumes only an incomplete response-required stream", () => {
    const base = {
      endedAtOutputLimit: false,
      responseToolAvailable: true,
      responseToolCalled: false,
      resumeCount: 0,
      aborted: false,
    };
    expect(shouldResumeMissingResponse(base)).toBe(true);
    expect(
      shouldResumeMissingResponse({ ...base, responseToolCalled: true }),
    ).toBe(false);
    expect(
      shouldResumeMissingResponse({ ...base, endedAtOutputLimit: true }),
    ).toBe(false);
    expect(shouldResumeMissingResponse({ ...base, resumeCount: 3 })).toBe(
      false,
    );
    expect(shouldResumeMissingResponse({ ...base, aborted: true })).toBe(false);
  });
});

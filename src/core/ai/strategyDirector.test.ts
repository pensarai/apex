import type { ModelMessage } from "ai";
import { describe, expect, it } from "vitest";
import {
  buildStrategyMessage,
  buildStrategyTranscript,
  latestResponseRejectionCount,
  shouldRunStrategyDirector,
} from "./strategyDirector";

describe("strategy director", () => {
  it("runs only on configured bounded cadence", () => {
    const state = {
      nextStepNumber: 0,
      reviewCount: 1,
      lastReviewedStep: 16,
    };
    const config = { intervalSteps: 16, maxReviews: 3 };

    expect(shouldRunStrategyDirector({ stepNumber: 32, state, config })).toBe(
      true,
    );
    expect(shouldRunStrategyDirector({ stepNumber: 31, state, config })).toBe(
      false,
    );
    expect(
      shouldRunStrategyDirector({
        stepNumber: 32,
        state: { ...state, reviewCount: 3 },
        config,
      }),
    ).toBe(false);
  });

  it("renders bounded evidence from calls and results", () => {
    const messages: ModelMessage[] = [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: "call-1",
            toolName: "http_request",
            input: { url: "http://target.test/health" },
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "call-1",
            toolName: "http_request",
            output: { type: "text", value: "200 healthy" },
          },
        ],
      },
    ];

    const transcript = buildStrategyTranscript(messages);
    expect(transcript).toContain("CALL http_request");
    expect(transcript).toContain("RESULT http_request");
    expect(transcript).toContain("200 healthy");
  });

  it("marks injected advice as harness-derived and evidence-bound", () => {
    const message = buildStrategyMessage("Retire the stale route guess.");
    expect(message.role).toBe("user");
    expect(String(message.content)).toContain("HARNESS STRATEGY CHECKPOINT");
    expect(String(message.content)).toContain("prior evidence");
  });

  it("detects a rejected response as an immediate strategy boundary", () => {
    const messages = [
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "response-1",
            toolName: "response",
            output: {
              type: "json",
              value: { responseRejected: true, rejectionCount: 2 },
            },
          },
        ],
      },
    ] as ModelMessage[];

    expect(latestResponseRejectionCount(messages)).toBe(2);
  });
});

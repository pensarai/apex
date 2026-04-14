/**
 * Unit tests for {@link ExplorationAgent}.
 *
 * Approach: we mock `getProviderModel` from `../../ai/utils` so that the
 * base harness's `streamResponse` call is served by a
 * `MockLanguageModelV3` instead of hitting a real provider. The mock
 * emits a single `ask_user_questions` tool-call, which both exercises
 * the `hasToolCall('ask_user_questions')` stop condition and lets us
 * verify that the messages surfaced via `streamResult.response` contain
 * the expected tool-call payload.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { MockLanguageModelV3, simulateReadableStream } from "ai/test";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";

// Mock the provider model factory BEFORE importing the agent/base class
// so the base harness's `streamResponse` resolves to the mock model.
vi.mock("../../ai/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../ai/utils")>();

  const stringifiedInput = JSON.stringify({
    questions: [
      {
        id: "deployment-runtime",
        question: "Where does this application actually run?",
        multiSelect: false,
        allowFreeform: true,
        options: [
          {
            id: "ecs-fargate",
            label: "AWS ECS Fargate (inferred from infra/ecs.ts)",
          },
          {
            id: "k8s",
            label: "Self-hosted Kubernetes (inferred from kubernetes/)",
          },
        ],
      },
    ],
  });

  const mockChunks: LanguageModelV3StreamPart[] = [
    { type: "stream-start", warnings: [] },
    {
      type: "response-metadata",
      id: "mock-response-1",
      timestamp: new Date(0),
      modelId: "mock-model",
    },
    {
      type: "tool-call",
      toolCallId: "tc_mock_1",
      toolName: "ask_user_questions",
      input: stringifiedInput,
    },
    {
      type: "finish",
      usage: {
        inputTokens: {
          total: 10,
          noCache: 10,
          cacheRead: 0,
          cacheWrite: 0,
        },
        outputTokens: {
          total: 20,
          text: 20,
          reasoning: 0,
        },
      },
      finishReason: { unified: "tool-calls", raw: "tool_use" },
    },
  ];

  const mockModel = new MockLanguageModelV3({
    provider: "mock-provider",
    modelId: "mock-model",
    doStream: async () => ({
      stream: simulateReadableStream({ chunks: mockChunks }),
    }),
  });

  return {
    ...actual,
    getProviderModel: () => mockModel,
  };
});

// Now safe to import — the mock is hoisted to the top of the file by
// vitest's `vi.mock`.
const { ExplorationAgent } = await import("./agent");
const { sessions } = await import("../../session");

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "exploration-agent-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe("ExplorationAgent", () => {
  it(
    "stops on ask_user_questions tool call and surfaces the tool-call in messages",
    async () => {
      // Construct a minimal session via the real factory — this gives
      // us all the paths and config defaults the base harness expects.
      const session = await sessions.create({
        name: "test-exploration",
        targets: [],
        config: { agentCwd: tmpDir },
      });

      const agent = new ExplorationAgent({
        prompt:
          "Explore the cloned repo and ask the operator for grounding context.",
        model: "claude-opus-4-6",
        session,
      });

      // consume() drains the stream, runs resolveResult (void here), and
      // returns. Under the mocked model, the single tool-call triggers
      // the hasToolCall('ask_user_questions') stop condition.
      await agent.consume();

      const response = await agent.streamResult.response;
      const messages = response.messages ?? [];

      // Find the assistant message that contains the ask_user_questions
      // tool-call. The base harness stores tool-calls inside an
      // assistant message's content array.
      let foundToolCall: {
        toolName: string;
        input: unknown;
      } | null = null;

      for (const msg of messages) {
        if (msg.role !== "assistant" || !Array.isArray(msg.content)) continue;
        for (const part of msg.content) {
          if (
            part.type === "tool-call" &&
            part.toolName === "ask_user_questions"
          ) {
            foundToolCall = {
              toolName: part.toolName,
              input: part.input,
            };
          }
        }
      }

      expect(
        foundToolCall,
        "expected messages to contain an ask_user_questions tool-call",
      ).not.toBeNull();
      expect(foundToolCall!.toolName).toBe("ask_user_questions");
      const input = foundToolCall!.input as {
        questions: Array<{ id: string; options: Array<{ label: string }> }>;
      };
      expect(Array.isArray(input.questions)).toBe(true);
      expect(input.questions.length).toBeGreaterThanOrEqual(1);
      // Grounding discipline: the mock emits a label with a filename
      // reference. Assert at least one option label contains a backtick
      // or filename-like token to guard against regressions where the
      // test fixture is accidentally stripped of grounding.
      const allLabels = input.questions.flatMap((q) =>
        q.options.map((o) => o.label),
      );
      expect(
        allLabels.some((l) => /\.(ts|yml|toml|json)\b|\//.test(l)),
        `expected at least one grounded option label, got: ${JSON.stringify(allLabels)}`,
      ).toBe(true);
    },
    15_000,
  );
});

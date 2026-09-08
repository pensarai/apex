import { stepCountIs } from "ai";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { streamResponse } from "../ai";

const liveEnabled =
  process.env.RUN_CONCENTRATE_INTEGRATION === "1" &&
  Boolean(process.env.CONCENTRATE_API_KEY);
const describeLive = liveEnabled ? describe : describe.skip;

describeLive("Concentrate GLM 5.3 live contract", () => {
  it(
    "streams reasoning through a two-turn tool call on the ZDR route",
    async () => {
      const apiKey = process.env.CONCENTRATE_API_KEY;
      if (!apiKey) throw new Error("CONCENTRATE_API_KEY is required");

      const resolvedModels: string[] = [];
      const usages: Array<{ input: number; output: number; cached: number }> = [];
      let reasoningParts = 0;
      let toolCalls = 0;
      let toolResults = 0;

      const response = streamResponse({
        model: "concentrate:glm-5.3",
        authConfig: { concentrateAPIKey: apiKey },
        system:
          "You are validating an inference transport. Follow the requested tool workflow exactly.",
        prompt:
          'Call the echo_probe tool exactly once with {"value":"probe"}, read its result, then answer with exactly DONE.',
        openAIReasoningEffort: "low",
        tools: {
          echo_probe: {
            description: "Return the supplied probe value.",
            inputSchema: z.object({ value: z.literal("probe") }),
            execute: async ({ value }: { value: "probe" }) => ({
              echoed: value,
            }),
          },
        },
        stopWhen: stepCountIs(3),
        onStepFinish: (step) => {
          if (step.response.modelId) {
            resolvedModels.push(step.response.modelId);
          }
          usages.push({
            input: step.usage.inputTokens ?? 0,
            output: step.usage.outputTokens ?? 0,
            cached: step.usage.inputTokenDetails.cacheReadTokens ?? 0,
          });
        },
      });

      for await (const part of response.fullStream) {
        if (part.type === "reasoning-delta") reasoningParts++;
        if (part.type === "tool-call") toolCalls++;
        if (part.type === "tool-result") toolResults++;
      }

      expect(await response.text).toBe("DONE");
      expect(reasoningParts).toBeGreaterThan(0);
      expect(toolCalls).toBe(1);
      expect(toolResults).toBe(1);
      expect(resolvedModels.length).toBeGreaterThan(0);
      expect(
        resolvedModels.every((model) => model === "fireworks/glm-5.3"),
      ).toBe(true);
      expect(
        usages.some(({ input, output }) => input > 0 && output > 0),
      ).toBe(true);
      expect(usages.every(({ cached }) => cached >= 0)).toBe(true);
    },
    180_000,
  );
});

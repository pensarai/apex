import { stepCountIs } from "ai";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { config } from "../../config";
import { streamResponse } from "../ai";
import { buildAuthConfig } from "../utils";

const describeLive =
  process.env.RUN_CUSTOM_INFERENCE_INTEGRATION === "1"
    ? describe
    : describe.skip;

describeLive("custom endpoint live contract", () => {
  it("completes a streamed tool round trip", async () => {
    const model = process.env.APEX_CUSTOM_MODEL;
    if (!model?.startsWith("custom:"))
      throw new Error("Set APEX_CUSTOM_MODEL to custom:<provider>:<model>.");
    let toolResults = 0;
    const response = streamResponse({
      model,
      authConfig: buildAuthConfig(await config.get()),
      prompt:
        'Call echo_probe exactly once with {"value":"probe"}, then answer DONE.',
      tools: {
        echo_probe: {
          description:
            "Return a synthetic probe value without accessing external systems.",
          inputSchema: z.object({ value: z.literal("probe") }),
          execute: async ({ value }: { value: "probe" }) => ({ echoed: value }),
        },
      },
      stopWhen: stepCountIs(3),
      abortSignal: AbortSignal.timeout(150_000),
    });
    for await (const part of response.fullStream) {
      if (part.type === "error") throw part.error;
      if (part.type === "tool-result") toolResults++;
    }
    expect(toolResults).toBe(1);
    expect((await response.text).trim()).toContain("DONE");
  }, 180_000);
});

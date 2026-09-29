import { stepCountIs } from "ai";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { config } from "../../config";
import { generateObjectResponse, streamResponse } from "../ai";
import { buildAuthConfig } from "../utils";

const describeLive =
  process.env.RUN_HOONIFY_INTEGRATION === "1" ? describe : describe.skip;

describeLive("Hoonify live contract", () => {
  it("discovers the model, streams a tool round trip, resumes, and produces structured output", async () => {
    const upstreamModel = process.env.HOONIFY_TEST_MODEL;
    if (!upstreamModel)
      throw new Error(
        "Set HOONIFY_TEST_MODEL to the exact model ID in your Hoonify catalog.",
      );
    const cfg = await config.get();
    if (cfg.hoonifyCatalogError) throw new Error(cfg.hoonifyCatalogError);
    const model = `hoonify:${upstreamModel}`;
    const authConfig = buildAuthConfig(cfg);
    let toolResults = 0;
    const run = streamResponse({
      model,
      authConfig,
      prompt:
        'Call echo_probe exactly once with {"value":"probe"}, then answer DONE.',
      tools: {
        echo_probe: {
          description:
            "Echo a synthetic value without accessing external systems.",
          inputSchema: z.object({ value: z.literal("probe") }),
          execute: async ({ value }: { value: "probe" }) => ({ echoed: value }),
        },
      },
      stopWhen: stepCountIs(3),
      abortSignal: AbortSignal.timeout(60_000),
      silent: true,
    });
    for await (const part of run.fullStream) {
      if (part.type === "error") throw part.error;
      if (part.type === "tool-result") toolResults++;
    }
    expect(toolResults).toBe(1);
    expect(await run.text).toContain("DONE");
    const resumed = streamResponse({
      model,
      authConfig,
      prompt: "",
      messages: [
        { role: "user", content: "Echo probe" },
        ...JSON.parse(JSON.stringify((await run.response).messages)),
        { role: "user", content: "What value did the echo tool return?" },
      ],
      abortSignal: AbortSignal.timeout(60_000),
      silent: true,
    });
    for await (const part of resumed.fullStream) {
      if (part.type === "error") throw part.error;
    }
    expect(await resumed.text).toContain("probe");
    expect(
      await generateObjectResponse({
        model,
        authConfig,
        prompt: "Return ok set to true.",
        schema: z.object({ ok: z.literal(true) }),
        abortSignal: AbortSignal.timeout(60_000),
      }),
    ).toEqual({ ok: true });
  }, 180_000);
});

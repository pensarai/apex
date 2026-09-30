import { createAnthropic } from "@ai-sdk/anthropic";
import type { LanguageModelV3 } from "@ai-sdk/provider";
import { wrapLanguageModel } from "ai";
import { getClaudeCapabilities, getMaxOutputTokens } from "../models";

export function createAnthropicModel(
  modelId: string,
  apiKey?: string,
): LanguageModelV3 {
  const capabilities = getClaudeCapabilities(modelId);
  if (!capabilities) return createAnthropic({ apiKey }).chat(modelId);

  const model = createAnthropic({
    apiKey,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      // The pinned SDK omits disabled thinking, but Claude 5 defaults to adaptive.
      body.thinking ??= {
        type: capabilities.alwaysOnThinking ? "adaptive" : "disabled",
      };
      const headers = new Headers(init?.headers);
      if (capabilities.bindsThinking) {
        // Context fitting can edit earlier turns; drop invalid bound blocks instead of failing.
        body.thinking.block_binding = {
          prefix_mismatch_behavior: "drop_block",
        };
        const beta = headers.get("anthropic-beta");
        headers.set(
          "anthropic-beta",
          [beta, "thinking-binding-controls-2026-08-01"]
            .filter(Boolean)
            .join(","),
        );
      }
      return globalThis.fetch(input, {
        ...init,
        headers,
        body: JSON.stringify(body),
      });
    }) as typeof fetch,
  }).chat(modelId);

  return wrapLanguageModel({
    model,
    middleware: {
      specificationVersion: "v3",
      transformParams: async ({ params }) => {
        const anthropic = params.providerOptions?.anthropic;
        const thinking = anthropic?.thinking as { type?: string } | undefined;
        return {
          ...params,
          maxOutputTokens:
            params.maxOutputTokens ?? getMaxOutputTokens(modelId),
          temperature: undefined,
          topP: undefined,
          topK: undefined,
          providerOptions: {
            ...params.providerOptions,
            anthropic: {
              ...anthropic,
              // Unknown model IDs otherwise fall back to a forced JSON tool.
              structuredOutputMode: "outputFormat",
              thinking:
                !capabilities.alwaysOnThinking && thinking?.type === "disabled"
                  ? { type: "disabled" }
                  : { type: "adaptive", display: "summarized" },
            },
          },
        };
      },
    },
  });
}

import type {
  LanguageModelV2,
  LanguageModelV2CallOptions,
  LanguageModelV2CallWarning,
  LanguageModelV2Content,
  LanguageModelV2FinishReason,
  LanguageModelV2StreamPart,
  LanguageModelV2Usage,
} from "@ai-sdk/provider";
import { convertToBedrockFormat, parseBedrockResponse } from "./pensarFormatters";

const DEBUG = process.env.PENSAR_DEBUG === "1" || process.env.PENSAR_DEBUG === "true";

function log(...args: unknown[]) {
  if (DEBUG) console.log("[pensar]", ...args);
}

function logError(...args: unknown[]) {
  console.error("[pensar]", ...args);
}

interface PensarModelConfig {
  apiKey: string;
  baseUrl: string;
}

/**
 * Creates a LanguageModelV2-compatible model that proxies requests through
 * the Pensar Console Bedrock proxy. This allows Apex CLI users to use
 * Pensar-managed inference with usage-based billing.
 *
 * MVP: Non-streaming. doStream() wraps doGenerate() in a ReadableStream
 * that emits a single chunk. True streaming requires Lambda Function URLs
 * with response streaming (follow-up work).
 */
export function createPensarModel(
  bedrockModelId: string,
  config: PensarModelConfig
): LanguageModelV2 {
  const modelId = `pensar:${bedrockModelId}`;

  const model: LanguageModelV2 = {
    specificationVersion: "v2",
    provider: "pensar",
    modelId,
    supportedUrls: {},

    async doGenerate(
      options: LanguageModelV2CallOptions
    ): Promise<{
      content: Array<LanguageModelV2Content>;
      finishReason: LanguageModelV2FinishReason;
      usage: LanguageModelV2Usage;
      providerMetadata?: undefined;
      request?: { body?: unknown };
      response?: { headers?: Record<string, string>; body?: unknown };
      warnings: Array<LanguageModelV2CallWarning>;
    }> {
      const body = convertToBedrockFormat(bedrockModelId, options);
      const url = `${config.baseUrl}/bedrock/invoke`;

      log(`doGenerate → ${bedrockModelId}`);
      log(`  URL: ${url}`);
      log(`  messages: ${(body.messages as unknown[])?.length ?? 0}, tools: ${(body.tools as unknown[])?.length ?? 0}`);

      const startTime = Date.now();

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({
          modelId: bedrockModelId,
          body,
          stream: false,
        }),
      });

      log(`  response: ${response.status} (${Date.now() - startTime}ms)`);

      if (!response.ok) {
        const errorBody = await response.text();
        let errorMessage: string;
        try {
          const parsed = JSON.parse(errorBody);
          errorMessage = parsed.error || parsed.message || errorBody;
        } catch {
          errorMessage = errorBody;
        }

        logError(`  FAILED ${response.status}: ${errorMessage}`);

        if (response.status === 402) {
          throw new Error(
            `Insufficient Pensar credits: ${errorMessage}. ` +
              `Top up at https://console.pensar.dev`
          );
        }

        throw new Error(
          `Pensar API error (${response.status}): ${errorMessage}`
        );
      }

      const result = (await response.json()) as {
        response: Record<string, unknown>;
        usage?: {
          inputTokens: number;
          outputTokens: number;
          totalCost: number;
        };
      };

      const usageFromProxy = result.usage ?? {
        inputTokens: 0,
        outputTokens: 0,
      };

      const parsed = parseBedrockResponse(bedrockModelId, result.response, {
        inputTokens: usageFromProxy.inputTokens,
        outputTokens: usageFromProxy.outputTokens,
      });

      log(`  finish: ${parsed.finishReason}, content: ${parsed.content.length} parts`);
      log(`  usage: ${parsed.usage.inputTokens}in / ${parsed.usage.outputTokens}out`);
      if (result.usage?.totalCost != null) {
        log(`  cost: $${result.usage.totalCost.toFixed(6)}`);
      }

      return {
        content: parsed.content,
        finishReason: parsed.finishReason,
        usage: parsed.usage,
        request: {
          body,
        },
        response: {
          body: result,
        },
        warnings: [],
      };
    },

    async doStream(
      options: LanguageModelV2CallOptions
    ): Promise<{
      stream: ReadableStream<LanguageModelV2StreamPart>;
      request?: { body?: unknown };
      response?: { headers?: Record<string, string> };
    }> {
      // MVP: Non-streaming fallback — call doGenerate and wrap in a stream.
      // The TUI sees text appear all at once rather than token-by-token.
      // True streaming via Lambda Function URL is a follow-up.
      log(`doStream → wrapping doGenerate for ${bedrockModelId}`);
      const generateResult = await model.doGenerate(options);

      const parts: LanguageModelV2StreamPart[] = [];

      // Emit stream-start
      parts.push({
        type: "stream-start",
        warnings: generateResult.warnings,
      });

      // Emit content parts
      for (const item of generateResult.content) {
        if (item.type === "text") {
          const id = `text-${Date.now()}`;
          parts.push({ type: "text-start", id });
          parts.push({ type: "text-delta", id, delta: item.text });
          parts.push({ type: "text-end", id });
        } else if (item.type === "tool-call") {
          const id = item.toolCallId;
          parts.push({
            type: "tool-input-start",
            id,
            toolName: item.toolName,
          });
          parts.push({
            type: "tool-input-delta",
            id,
            delta: item.input,
          });
          parts.push({ type: "tool-input-end", id });
          parts.push({
            type: "tool-call",
            toolCallId: id,
            toolName: item.toolName,
            input: item.input,
          });
        }
      }

      // Emit finish
      parts.push({
        type: "finish",
        finishReason: generateResult.finishReason,
        usage: generateResult.usage,
      });

      const stream = new ReadableStream<LanguageModelV2StreamPart>({
        start(controller) {
          for (const part of parts) {
            controller.enqueue(part);
          }
          controller.close();
        },
      });

      return {
        stream,
        request: {
          body: generateResult.request?.body,
        },
      };
    },
  };

  return model;
}

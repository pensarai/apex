import type {
  LanguageModelV2,
  LanguageModelV2CallOptions,
  LanguageModelV2CallWarning,
  LanguageModelV2Content,
  LanguageModelV2FinishReason,
  LanguageModelV2StreamPart,
  LanguageModelV2Usage,
} from "@ai-sdk/provider";
import {
  convertToBedrockFormat,
  parseBedrockResponse,
} from "./pensarFormatters";
import { parseSSE } from "./pensarSSE";

const DEBUG =
  process.env.PENSAR_DEBUG === "1" || process.env.PENSAR_DEBUG === "true";

function log(...args: unknown[]) {
  if (DEBUG) console.log("[pensar]", ...args);
}

function logError(...args: unknown[]) {
  console.error("[pensar]", ...args);
}

export interface PensarModelConfig {
  apiKey: string;
  baseUrl: string;
  /** Workspace ID for WorkOS-authenticated requests. */
  workspaceId?: string;
  /**
   * Optional callback to get a fresh token before each request.
   * If provided, this is called instead of using `apiKey` directly,
   * allowing transparent token refresh for WorkOS auth.
   */
  getToken?: () => Promise<{ token: string; type: "workos" | "legacy" } | null>;
  /** Optional explicit stream URL. If not set, discovered via /bedrock/validate. */
  streamUrl?: string;
}

/**
 * Creates a LanguageModelV2-compatible model that proxies requests through
 * the Pensar Console Bedrock proxy. This allows Apex CLI users to use
 * Pensar-managed inference with usage-based billing.
 *
 * Supports both legacy API key auth and WorkOS JWT auth.
 * When workspaceId is provided, sends X-Workspace-Id header for WorkOS auth.
 *
 * doStream() posts to /bedrock/stream and parses SSE events for real
 * token-by-token streaming. Falls back to wrapping doGenerate() on error.
 */
export function createPensarModel(
  bedrockModelId: string,
  config: PensarModelConfig,
): LanguageModelV2 {
  const modelId = `pensar:${bedrockModelId}`;

  /**
   * Build request headers, resolving the token via getToken() if available.
   */
  async function buildHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (config.getToken) {
      const result = await config.getToken();
      if (!result) {
        throw new Error(
          "Pensar authentication failed. Run /auth to reconnect.",
        );
      }
      headers.Authorization = `Bearer ${result.token}`;

      // WorkOS tokens need workspace ID header
      if (result.type === "workos" && config.workspaceId) {
        headers["X-Workspace-Id"] = config.workspaceId;
      }
    } else {
      headers.Authorization = `Bearer ${config.apiKey}`;

      // If workspaceId is set and key doesn't look like a legacy key,
      // include the workspace header
      if (config.workspaceId && !config.apiKey.startsWith("sk-")) {
        headers["X-Workspace-Id"] = config.workspaceId;
      }
    }

    return headers;
  }

  // ── Stream URL discovery ─────────────────────────────────────────────
  let cachedStreamUrl: string | null = null;

  async function getStreamUrl(): Promise<string> {
    if (cachedStreamUrl) return cachedStreamUrl;

    // Try to discover Lambda Function URL from /bedrock/validate
    try {
      const headers = await buildHeaders();
      const res = await fetch(`${config.baseUrl}/bedrock/validate`, {
        headers,
      });
      if (res.ok) {
        const data = (await res.json()) as {
          endpoints?: { stream?: string };
        };
        if (data.endpoints?.stream) {
          cachedStreamUrl = data.endpoints.stream;
          log(`  Discovered stream URL: ${cachedStreamUrl}`);
          return cachedStreamUrl;
        }
      }
    } catch {
      // Fall through to fallback
    }

    // Fallback: buffered SSE via API Gateway
    cachedStreamUrl = `${config.baseUrl}/bedrock/stream`;
    log(`  Using fallback stream URL: ${cachedStreamUrl}`);
    return cachedStreamUrl;
  }

  const model: LanguageModelV2 = {
    specificationVersion: "v2",
    provider: "pensar",
    modelId,
    supportedUrls: {},

    async doGenerate(options: LanguageModelV2CallOptions): Promise<{
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
      log(
        `  messages: ${(body.messages as unknown[])?.length ?? 0}, tools: ${(body.tools as unknown[])?.length ?? 0}`,
      );

      const startTime = Date.now();
      const headers = await buildHeaders();

      const response = await fetch(url, {
        method: "POST",
        headers,
        signal: options.abortSignal,
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
              `Top up at https://console.pensar.dev`,
          );
        }

        throw new Error(
          `Pensar API error (${response.status}): ${errorMessage}`,
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

      log(
        `  finish: ${parsed.finishReason}, content: ${parsed.content.length} parts`,
      );
      log(
        `  usage: ${parsed.usage.inputTokens}in / ${parsed.usage.outputTokens}out`,
      );
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

    async doStream(options: LanguageModelV2CallOptions): Promise<{
      stream: ReadableStream<LanguageModelV2StreamPart>;
      request?: { body?: unknown };
      response?: { headers?: Record<string, string> };
    }> {
      const body = convertToBedrockFormat(bedrockModelId, options);
      const url = config.streamUrl ?? (await getStreamUrl());

      log(`doStream → SSE streaming for ${bedrockModelId}`);
      log(`  URL: ${url}`);

      const headers = await buildHeaders();

      let response: Response;
      try {
        response = await fetch(url, {
          method: "POST",
          headers,
          signal: options.abortSignal,
          body: JSON.stringify({
            modelId: bedrockModelId,
            body,
          }),
        });
      } catch (err) {
        // Network error — fall back to non-streaming
        logError(`  SSE fetch failed, falling back to doGenerate:`, err);
        return doStreamFallback(model, options);
      }

      if (!response.ok) {
        const errorBody = await response.text();
        let errorMessage: string;
        try {
          const parsed = JSON.parse(errorBody);
          errorMessage = parsed.error || parsed.message || errorBody;
        } catch {
          errorMessage = errorBody;
        }
        logError(`  SSE FAILED ${response.status}: ${errorMessage}`);

        if (response.status === 402) {
          throw new Error(
            `Insufficient Pensar credits: ${errorMessage}. ` +
              `Top up at https://console.pensar.dev`,
          );
        }
        throw new Error(
          `Pensar streaming error (${response.status}): ${errorMessage}`,
        );
      }

      if (!response.body) {
        logError(`  SSE response has no body, falling back to doGenerate`);
        return doStreamFallback(model, options);
      }

      const sseStream = response.body;

      const stream = new ReadableStream<LanguageModelV2StreamPart>({
        async start(controller) {
          let inputTokens = 0;
          let outputTokens = 0;
          let finishReason: LanguageModelV2FinishReason = "unknown";
          let startEmitted = false;
          // Track active content blocks for proper id mapping
          let activeTextId: string | null = null;
          let activeToolId: string | null = null;
          let activeToolName: string | null = null;
          let activeToolInput = "";

          try {
            for await (const sse of parseSSE(sseStream)) {
              let parsed: Record<string, unknown>;
              try {
                parsed = JSON.parse(sse.data);
              } catch {
                continue;
              }

              if (sse.event === "error") {
                const msg =
                  (parsed.error as string) ?? "Unknown streaming error";
                controller.error(new Error(msg));
                return;
              }

              // Ignore pensar:usage — it's informational
              if (sse.event === "pensar:usage") {
                if (parsed.totalCost != null) {
                  log(`  cost: $${Number(parsed.totalCost).toFixed(6)}`);
                }
                continue;
              }

              const type = parsed.type as string;

              switch (type) {
                case "message_start": {
                  if (!startEmitted) {
                    controller.enqueue({ type: "stream-start", warnings: [] });
                    startEmitted = true;
                  }
                  const msg = parsed.message as
                    | Record<string, unknown>
                    | undefined;
                  const usage = msg?.usage as
                    | Record<string, number>
                    | undefined;
                  if (usage?.input_tokens) {
                    inputTokens = usage.input_tokens;
                  }
                  break;
                }

                case "content_block_start": {
                  if (!startEmitted) {
                    controller.enqueue({ type: "stream-start", warnings: [] });
                    startEmitted = true;
                  }
                  const cb = parsed.content_block as
                    | Record<string, unknown>
                    | undefined;
                  const cbType = cb?.type as string | undefined;
                  if (cbType === "text") {
                    activeTextId = `text-${Date.now()}-${parsed.index}`;
                    controller.enqueue({
                      type: "text-start",
                      id: activeTextId,
                    });
                  } else if (cbType === "tool_use") {
                    activeToolId = (cb?.id as string) ?? `tool-${Date.now()}`;
                    activeToolName = (cb?.name as string) ?? "unknown";
                    activeToolInput = "";
                    controller.enqueue({
                      type: "tool-input-start",
                      id: activeToolId,
                      toolName: activeToolName,
                    });
                  }
                  break;
                }

                case "content_block_delta": {
                  const delta = parsed.delta as
                    | Record<string, unknown>
                    | undefined;
                  const deltaType = delta?.type as string | undefined;
                  if (deltaType === "text_delta" && activeTextId) {
                    controller.enqueue({
                      type: "text-delta",
                      id: activeTextId,
                      delta: (delta?.text as string) ?? "",
                    });
                  } else if (deltaType === "input_json_delta" && activeToolId) {
                    const jsonDelta = (delta?.partial_json as string) ?? "";
                    activeToolInput += jsonDelta;
                    controller.enqueue({
                      type: "tool-input-delta",
                      id: activeToolId,
                      delta: jsonDelta,
                    });
                  }
                  break;
                }

                case "content_block_stop": {
                  if (activeTextId) {
                    controller.enqueue({ type: "text-end", id: activeTextId });
                    activeTextId = null;
                  } else if (activeToolId && activeToolName) {
                    controller.enqueue({
                      type: "tool-input-end",
                      id: activeToolId,
                    });
                    controller.enqueue({
                      type: "tool-call",
                      toolCallId: activeToolId,
                      toolName: activeToolName,
                      input: activeToolInput,
                    });
                    activeToolId = null;
                    activeToolName = null;
                    activeToolInput = "";
                  }
                  break;
                }

                case "message_delta": {
                  const delta = parsed.delta as
                    | Record<string, unknown>
                    | undefined;
                  const stopReason = delta?.stop_reason as string | undefined;
                  if (stopReason) {
                    finishReason = mapStopReason(stopReason);
                  }
                  const usage = parsed.usage as
                    | Record<string, number>
                    | undefined;
                  if (usage?.output_tokens) {
                    outputTokens = usage.output_tokens;
                  }
                  break;
                }

                case "message_stop": {
                  // Stream complete
                  break;
                }
              }
            }

            log(
              `  stream done: ${finishReason}, ${inputTokens}in/${outputTokens}out`,
            );

            controller.enqueue({
              type: "finish",
              finishReason,
              usage: {
                inputTokens,
                outputTokens,
                totalTokens: inputTokens + outputTokens,
              },
            });
            controller.close();
          } catch (err) {
            controller.error(err);
          }
        },
      });

      return {
        stream,
        request: { body },
      };
    },
  };

  return model;
}

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Map Anthropic stop_reason strings to LanguageModelV2FinishReason.
 */
function mapStopReason(reason: string): LanguageModelV2FinishReason {
  switch (reason) {
    case "end_turn":
      return "stop";
    case "max_tokens":
      return "length";
    case "tool_use":
      return "tool-calls";
    case "stop_sequence":
      return "stop";
    default:
      return "unknown";
  }
}

/**
 * Non-streaming fallback: call doGenerate and wrap in a ReadableStream.
 * Used when streaming fails or is not available.
 */
async function doStreamFallback(
  model: LanguageModelV2,
  options: LanguageModelV2CallOptions,
): Promise<{
  stream: ReadableStream<LanguageModelV2StreamPart>;
  request?: { body?: unknown };
  response?: { headers?: Record<string, string> };
}> {
  const generateResult = await model.doGenerate(options);

  const parts: LanguageModelV2StreamPart[] = [];

  parts.push({ type: "stream-start", warnings: generateResult.warnings });

  for (const item of generateResult.content) {
    if (item.type === "text") {
      const id = `text-${Date.now()}`;
      parts.push({ type: "text-start", id });
      parts.push({ type: "text-delta", id, delta: item.text });
      parts.push({ type: "text-end", id });
    } else if (item.type === "tool-call") {
      const id = item.toolCallId;
      parts.push({ type: "tool-input-start", id, toolName: item.toolName });
      parts.push({ type: "tool-input-delta", id, delta: item.input });
      parts.push({ type: "tool-input-end", id });
      parts.push({
        type: "tool-call",
        toolCallId: id,
        toolName: item.toolName,
        input: item.input,
      });
    }
  }

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

  return { stream, request: { body: generateResult.request?.body } };
}

import type {
  LanguageModelV3,
  LanguageModelV3CallOptions,
  LanguageModelV3Content,
  LanguageModelV3FinishReason,
  LanguageModelV3StreamPart,
  LanguageModelV3Usage,
  SharedV3Warning,
} from "@ai-sdk/provider";
import { convertToBedrockFormat } from "./pensarFormatters";
import { parseSSE } from "./pensarSSE";
import { signGatewayRequest } from "./pensarSigning";
import { buildStreamingFetchSignal } from "../utils";

const DEBUG =
  process.env.PENSAR_DEBUG === "1" || process.env.PENSAR_DEBUG === "true";

function log(...args: unknown[]) {
  if (DEBUG) console.error("[pensar:debug]", ...args);
}

function logInfo(...args: unknown[]) {
  console.error("[pensar]", ...args);
}

function logError(...args: unknown[]) {
  console.error("[pensar:error]", ...args);
}

export interface PensarModelConfig {
  apiKey: string;
  baseUrl: string;
  /** Workspace ID for WorkOS-authenticated requests. */
  workspaceId?: string;
  /**
   * Server-issued HMAC signing key for request authentication.
   * When present, every inference request is signed with this key.
   */
  signingKey?: string;
  /**
   * Optional callback to get a fresh token before each request.
   * If provided, this is called instead of using `apiKey` directly,
   * allowing transparent token refresh for WorkOS auth.
   */
  getToken?: () => Promise<{ token: string; type: "workos" | "legacy" } | null>;
}

/**
 * Creates a LanguageModelV2-compatible model that proxies requests through
 * the Pensar Gateway. This allows Apex CLI users to use Pensar-managed
 * inference with usage-based billing.
 *
 * Supports both legacy API key auth and WorkOS JWT auth.
 * When workspaceId is provided, sends X-Workspace-Id header for WorkOS auth.
 *
 * Both doGenerate() and doStream() use the same /gateway/invoke endpoint.
 * doGenerate() delegates to doStream() and collects the full result.
 * Streaming is true SSE via the Pensar Gateway.
 */
export function createPensarModel(
  bedrockModelId: string,
  config: PensarModelConfig,
): LanguageModelV3 {
  const modelId = `pensar:${bedrockModelId}`;
  logInfo(
    `createPensarModel: model=${bedrockModelId}, baseUrl=${config.baseUrl}`,
  );

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
        logError("buildHeaders: getToken() returned null — auth failed");
        throw new Error(
          "Pensar authentication failed. Run /login to reconnect.",
        );
      }
      headers.Authorization = `Bearer ${result.token.slice(0, 12)}…`;
      log(`  auth: ${result.type} token (${result.token.length} chars)`);

      if (config.workspaceId) {
        headers["X-Workspace-Id"] = config.workspaceId;
      }

      // Restore the full token after logging the truncated version
      headers.Authorization = `Bearer ${result.token}`;
    } else {
      headers.Authorization = `Bearer ${config.apiKey}`;
      log(`  auth: apiKey (${config.apiKey.length} chars)`);

      if (config.workspaceId && !config.apiKey.startsWith("sk-")) {
        headers["X-Workspace-Id"] = config.workspaceId;
      }
    }

    return headers;
  }

  const model: LanguageModelV3 = {
    specificationVersion: "v3",
    provider: "pensar",
    modelId,
    supportedUrls: {},

    async doGenerate(options: LanguageModelV3CallOptions): Promise<{
      content: Array<LanguageModelV3Content>;
      finishReason: LanguageModelV3FinishReason;
      usage: LanguageModelV3Usage;
      providerMetadata?: undefined;
      request?: { body?: unknown };
      response?: { headers?: Record<string, string>; body?: unknown };
      warnings: Array<SharedV3Warning>;
    }> {
      logInfo(`doGenerate → streaming and collecting for ${bedrockModelId}`);
      const startTime = Date.now();

      const { stream } = await model.doStream(options);
      const content: LanguageModelV3Content[] = [];
      let finishReason: LanguageModelV3FinishReason = {
        unified: "other",
        raw: undefined,
      };
      let usage: LanguageModelV3Usage = {
        inputTokens: {
          total: 0,
          noCache: undefined,
          cacheRead: undefined,
          cacheWrite: undefined,
        },
        outputTokens: { total: 0, text: undefined, reasoning: undefined },
      };

      const textParts: Record<string, string> = {};
      const reasoningParts: Record<
        string,
        {
          text: string;
          providerMetadata?: Record<string, Record<string, unknown>>;
        }
      > = {};
      const toolInputParts: Record<
        string,
        { toolName: string; input: string }
      > = {};

      const reader = stream.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          switch (value.type) {
            case "reasoning-start":
              reasoningParts[value.id] = { text: "" };
              break;
            case "reasoning-delta":
              if (reasoningParts[value.id]) {
                reasoningParts[value.id].text += value.delta;
              }
              break;
            case "reasoning-end":
              if (reasoningParts[value.id]) {
                content.push({
                  type: "reasoning",
                  text: reasoningParts[value.id].text,
                  providerMetadata: value.providerMetadata,
                });
              }
              break;
            case "text-start":
              textParts[value.id] = "";
              break;
            case "text-delta":
              textParts[value.id] = (textParts[value.id] ?? "") + value.delta;
              break;
            case "text-end":
              content.push({
                type: "text",
                text: textParts[value.id] ?? "",
              });
              break;
            case "tool-input-start":
              toolInputParts[value.id] = {
                toolName: value.toolName,
                input: "",
              };
              break;
            case "tool-input-delta":
              if (toolInputParts[value.id]) {
                toolInputParts[value.id].input += value.delta;
              }
              break;
            case "tool-call":
              content.push({
                type: "tool-call",
                toolCallId: value.toolCallId,
                toolName: value.toolName,
                input: value.input,
              });
              break;
            case "finish":
              finishReason = value.finishReason;
              usage = value.usage;
              break;
          }
        }
      } finally {
        reader.releaseLock();
      }

      logInfo(
        `  doGenerate complete: ${finishReason.unified}, ${content.length} parts, ${usage.inputTokens.total ?? 0}in/${usage.outputTokens.total ?? 0}out (${Date.now() - startTime}ms)`,
      );

      return {
        content,
        finishReason,
        usage,
        warnings: [],
      };
    },

    async doStream(options: LanguageModelV3CallOptions): Promise<{
      stream: ReadableStream<LanguageModelV3StreamPart>;
      request?: { body?: unknown };
      response?: { headers?: Record<string, string> };
    }> {
      const body = convertToBedrockFormat(bedrockModelId, options);
      const url = `${config.baseUrl}/gateway/invoke`;

      logInfo(`doStream → ${bedrockModelId} (${url})`);
      log(
        `  messages: ${(body.messages as unknown[])?.length ?? 0}, tools: ${(body.tools as unknown[])?.length ?? 0}`,
      );

      const startTime = Date.now();
      const serializedBody = JSON.stringify({
        modelId: bedrockModelId,
        body,
      });
      const headers = await buildHeaders();

      if (config.signingKey) {
        const sig = signGatewayRequest(
          config.signingKey,
          bedrockModelId,
          serializedBody,
        );
        headers["X-Pensar-Signature"] = sig.signature;
        headers["X-Pensar-Timestamp"] = sig.timestamp;
        headers["X-Pensar-Nonce"] = sig.nonce;
      }

      log(`  headers: ${Object.keys(headers).join(", ")}`);

      const fetchSignal = buildStreamingFetchSignal(options.abortSignal);

      let response: Response;
      try {
        response = await fetch(url, {
          method: "POST",
          headers,
          signal: fetchSignal,
          body: serializedBody,
        });
      } catch (err) {
        logError(`  SSE fetch failed (${Date.now() - startTime}ms):`, err);
        throw new Error(
          `Pensar Gateway request failed: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }

      const contentType = response.headers.get("content-type") ?? "unknown";
      const transferEncoding =
        response.headers.get("transfer-encoding") ?? "none";
      logInfo(
        `  response: ${response.status} (${Date.now() - startTime}ms) content-type=${contentType} transfer-encoding=${transferEncoding}`,
      );

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
        logError(`  SSE response has no body (${Date.now() - startTime}ms)`);
        throw new Error("Pensar Gateway returned an empty response body");
      }

      logInfo(`  SSE stream opened, reading events...`);

      const sseStream = response.body;

      const abortSignal = options.abortSignal;
      const stream = new ReadableStream<LanguageModelV3StreamPart>({
        async start(controller) {
          let inputTokens = 0;
          let outputTokens = 0;
          let cacheReadTokens = 0;
          let cacheCreationTokens = 0;
          let finishReasonUnified: LanguageModelV3FinishReason["unified"] =
            "other";
          let finishReasonRaw: string | undefined;
          let startEmitted = false;
          // Track active content blocks for proper id mapping
          let activeTextId: string | null = null;
          let activeReasoningId: string | null = null;
          let activeReasoningSignature: string | null = null;
          let activeToolId: string | null = null;
          let activeToolName: string | null = null;
          let activeToolInput = "";

          if (abortSignal) {
            abortSignal.addEventListener(
              "abort",
              () => {
                logError(
                  `  abort signal fired during stream (reason=${abortSignal.reason}), activeToolId=${activeToolId}, activeToolName=${activeToolName}, inputLen=${activeToolInput.length}`,
                );
                logError(`  abort stack: ${new Error("abort-trace").stack}`);
              },
              { once: true },
            );
          }

          let eventCount = 0;
          let lastEventTime = Date.now();
          const idleTimeoutMs = Number(
            process.env.PENSAR_SSE_IDLE_TIMEOUT_MS ?? 90_000,
          );
          try {
            for await (const sse of parseSSE(sseStream, { idleTimeoutMs })) {
              const now = Date.now();
              const gap = now - lastEventTime;
              if (gap > 5000) {
                logInfo(
                  `  SSE gap: ${gap}ms between events (event #${eventCount + 1})`,
                );
              }
              lastEventTime = now;
              eventCount++;
              let parsed: Record<string, unknown>;
              try {
                parsed = JSON.parse(sse.data);
              } catch {
                log(`  SSE event #${eventCount}: unparseable data, skipping`);
                continue;
              }

              log(
                `  SSE event #${eventCount}: ${sse.event} (type=${parsed.type})`,
              );

              if (sse.event === "error") {
                const msg =
                  (parsed.error as string) ?? "Unknown streaming error";
                logError(`  SSE error event: ${msg}`);
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
                  if (usage?.cache_read_input_tokens) {
                    cacheReadTokens = usage.cache_read_input_tokens;
                  }
                  if (usage?.cache_creation_input_tokens) {
                    cacheCreationTokens = usage.cache_creation_input_tokens;
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
                  if (cbType === "thinking") {
                    activeReasoningId = `reasoning-${Date.now()}-${parsed.index}`;
                    activeReasoningSignature = null;
                    controller.enqueue({
                      type: "reasoning-start",
                      id: activeReasoningId,
                    });
                  } else if (cbType === "text") {
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
                  if (deltaType === "thinking_delta" && activeReasoningId) {
                    controller.enqueue({
                      type: "reasoning-delta",
                      id: activeReasoningId,
                      delta: (delta?.thinking as string) ?? "",
                    });
                  } else if (
                    deltaType === "signature_delta" &&
                    activeReasoningId
                  ) {
                    activeReasoningSignature =
                      (activeReasoningSignature ?? "") +
                      ((delta?.signature as string) ?? "");
                  } else if (deltaType === "text_delta" && activeTextId) {
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
                  if (activeReasoningId) {
                    controller.enqueue({
                      type: "reasoning-end",
                      id: activeReasoningId,
                      ...(activeReasoningSignature && {
                        providerMetadata: {
                          anthropic: { signature: activeReasoningSignature },
                        },
                      }),
                    });
                    activeReasoningId = null;
                    activeReasoningSignature = null;
                  } else if (activeTextId) {
                    controller.enqueue({ type: "text-end", id: activeTextId });
                    activeTextId = null;
                  } else if (activeToolId && activeToolName) {
                    logInfo(
                      `  tool-call complete: ${activeToolName} (${activeToolId}), inputLen=${activeToolInput.length}`,
                    );
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
                    finishReasonUnified = mapStopReason(stopReason);
                    finishReasonRaw = stopReason;
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

            logInfo(
              `  stream complete: ${finishReasonUnified}, ${inputTokens}in/${outputTokens}out, cacheRead=${cacheReadTokens}, cacheWrite=${cacheCreationTokens} (${Date.now() - startTime}ms)`,
            );

            controller.enqueue({
              type: "finish",
              finishReason: {
                unified: finishReasonUnified,
                raw: finishReasonRaw,
              },
              usage: {
                inputTokens: {
                  total: inputTokens,
                  noCache: undefined,
                  cacheRead: cacheReadTokens || undefined,
                  cacheWrite: cacheCreationTokens || undefined,
                },
                outputTokens: {
                  total: outputTokens,
                  text: undefined,
                  reasoning: undefined,
                },
              },
            });
            controller.close();
          } catch (err) {
            logError(
              `  stream error: events=${eventCount}, activeToolId=${activeToolId}, activeToolName=${activeToolName}, toolInputLen=${activeToolInput.length}, timeSinceLastEvent=${Date.now() - lastEventTime}ms`,
            );
            logError(`  stream error:`, err);
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

function mapStopReason(reason: string): LanguageModelV3FinishReason["unified"] {
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
      return "other";
  }
}

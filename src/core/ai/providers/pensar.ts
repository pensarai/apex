import type {
  LanguageModelV2,
  LanguageModelV2CallOptions,
  LanguageModelV2CallWarning,
  LanguageModelV2Content,
  LanguageModelV2FinishReason,
  LanguageModelV2StreamPart,
  LanguageModelV2Usage,
} from "@ai-sdk/provider";
import { convertToBedrockFormat } from "./pensarFormatters";
import { parseSSE } from "./pensarSSE";
import { signGatewayRequest } from "./pensarSigning";

const DEBUG =
  process.env.PENSAR_DEBUG === "1" || process.env.PENSAR_DEBUG === "true";

const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000;
const MAX_RETRY_DELAY_MS = 10000;

const RETRYABLE_STATUS_CODES = new Set([
  408, // Request Timeout
  409, // Conflict (often connection closed unexpectedly)
  429, // Too Many Requests
  500, // Internal Server Error
  502, // Bad Gateway
  503, // Service Unavailable
  504, // Gateway Timeout
]);

const RETRYABLE_ERROR_PATTERNS = [
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EPIPE",
  "ENETUNREACH",
  "EAI_AGAIN",
  "socket hang up",
  "connection closed",
  "network error",
  "fetch failed",
];

function log(...args: unknown[]) {
  if (DEBUG) console.error("[pensar:debug]", ...args);
}

function logInfo(...args: unknown[]) {
  console.error("[pensar]", ...args);
}

function logError(...args: unknown[]) {
  console.error("[pensar:error]", ...args);
}

function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    const name = error.name.toLowerCase();
    return RETRYABLE_ERROR_PATTERNS.some(
      (pattern) =>
        message.includes(pattern.toLowerCase()) ||
        name.includes(pattern.toLowerCase()),
    );
  }
  return false;
}

function isRetryableStatusCode(status: number): boolean {
  return RETRYABLE_STATUS_CODES.has(status);
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getRetryDelay(attempt: number): number {
  const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
  const jitter = Math.random() * 0.3 * delay;
  return Math.min(delay + jitter, MAX_RETRY_DELAY_MS);
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
): LanguageModelV2 {
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
          "Pensar authentication failed. Run /auth to reconnect.",
        );
      }
      headers.Authorization = `Bearer ${result.token.slice(0, 12)}…`;
      log(`  auth: ${result.type} token (${result.token.length} chars)`);

      if (result.type === "workos" && config.workspaceId) {
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
      logInfo(`doGenerate → streaming and collecting for ${bedrockModelId}`);
      const startTime = Date.now();

      const { stream } = await model.doStream(options);
      const content: LanguageModelV2Content[] = [];
      let finishReason: LanguageModelV2FinishReason = "unknown";
      let usage: LanguageModelV2Usage = {
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
      };

      const textParts: Record<string, string> = {};
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
        `  doGenerate complete: ${finishReason}, ${content.length} parts, ${usage.inputTokens}in/${usage.outputTokens}out (${Date.now() - startTime}ms)`,
      );

      return {
        content,
        finishReason,
        usage,
        warnings: [],
      };
    },

    async doStream(options: LanguageModelV2CallOptions): Promise<{
      stream: ReadableStream<LanguageModelV2StreamPart>;
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

      let response: Response | null = null;
      let lastError: Error | null = null;

      for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
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

        if (attempt > 0) {
          logInfo(`  retry attempt ${attempt}/${MAX_RETRIES}...`);
        }
        log(`  headers: ${Object.keys(headers).join(", ")}`);

        try {
          response = await fetch(url, {
            method: "POST",
            headers,
            signal: options.abortSignal,
            body: serializedBody,
          });

          const contentType = response.headers.get("content-type") ?? "unknown";
          const transferEncoding =
            response.headers.get("transfer-encoding") ?? "none";
          logInfo(
            `  response: ${response.status} (${Date.now() - startTime}ms) content-type=${contentType} transfer-encoding=${transferEncoding}`,
          );

          if (response.ok) {
            break;
          }

          const errorBody = await response.text();
          let errorMessage: string;
          try {
            const parsed = JSON.parse(errorBody);
            errorMessage = parsed.error || parsed.message || errorBody;
          } catch {
            errorMessage = errorBody;
          }

          if (response.status === 402) {
            throw new Error(
              `Insufficient Pensar credits: ${errorMessage}. ` +
                `Top up at https://console.pensar.dev`,
            );
          }

          if (response.status === 401 || response.status === 403) {
            throw new Error(
              `Pensar authentication error (${response.status}): ${errorMessage}`,
            );
          }

          lastError = new Error(
            `Pensar streaming error (${response.status}): ${errorMessage}`,
          );

          if (
            isRetryableStatusCode(response.status) &&
            attempt < MAX_RETRIES
          ) {
            const delay = getRetryDelay(attempt);
            logInfo(
              `  retryable error ${response.status}, waiting ${Math.round(delay)}ms before retry...`,
            );
            await sleep(delay);
            continue;
          }

          logError(`  SSE FAILED ${response.status}: ${errorMessage}`);
          throw lastError;
        } catch (err) {
          if (
            err instanceof Error &&
            (err.message.includes("Insufficient Pensar credits") ||
              err.message.includes("authentication error"))
          ) {
            throw err;
          }

          lastError =
            err instanceof Error
              ? err
              : new Error(`Pensar Gateway request failed: ${String(err)}`, {
                  cause: err,
                });

          if (options.abortSignal?.aborted) {
            logError(`  request aborted by user`);
            throw lastError;
          }

          if (isRetryableError(err) && attempt < MAX_RETRIES) {
            const delay = getRetryDelay(attempt);
            logInfo(
              `  connection error: ${lastError.message}, waiting ${Math.round(delay)}ms before retry...`,
            );
            await sleep(delay);
            continue;
          }

          logError(`  SSE fetch failed (${Date.now() - startTime}ms):`, err);
          throw new Error(
            `Pensar Gateway request failed after ${attempt + 1} attempt(s): ${lastError.message}. ` +
              `This may be a temporary network issue. Please try again.`,
            { cause: err },
          );
        }
      }

      if (!response || !response.ok) {
        throw (
          lastError ??
          new Error("Pensar Gateway request failed after all retries")
        );
      }

      if (!response.body) {
        logError(`  SSE response has no body (${Date.now() - startTime}ms)`);
        throw new Error("Pensar Gateway returned an empty response body");
      }

      logInfo(`  SSE stream opened, reading events...`);

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

          let eventCount = 0;
          try {
            for await (const sse of parseSSE(sseStream)) {
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

            logInfo(
              `  stream complete: ${finishReason}, ${inputTokens}in/${outputTokens}out (${Date.now() - startTime}ms)`,
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
            const errorMessage =
              err instanceof Error ? err.message : String(err);
            logError(`  stream error:`, err);

            if (
              errorMessage.toLowerCase().includes("connection") ||
              errorMessage.toLowerCase().includes("network") ||
              errorMessage.toLowerCase().includes("aborted") ||
              errorMessage.toLowerCase().includes("socket") ||
              errorMessage.includes("ECONNRESET") ||
              errorMessage.includes("EPIPE")
            ) {
              controller.error(
                new Error(
                  `Connection interrupted during inference streaming: ${errorMessage}. ` +
                    `This is typically a temporary network issue. Please try again.`,
                ),
              );
            } else {
              controller.error(err);
            }
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

import type {
  LanguageModelV3FinishReason,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import { createLogger } from "../../logger/structured";
import { scopedLogger } from "../../util/lazyLogger";
import { parseSSE } from "./pensarSSE";

const structuredLog = scopedLogger(() => createLogger("pensar:responses"));

export interface ResponsesStreamOptions {
  abortSignal?: AbortSignal;
  idleTimeoutMs: number;
}

interface PendingToolCall {
  callId: string;
  name: string;
  args: string;
}

/**
 * Parse the OpenAI Responses API SSE stream (as relayed by the Pensar Gateway
 * for Bedrock Mantle GPT-5.x models) into AI-SDK `LanguageModelV3StreamPart`s.
 *
 * Mirrors the structure of the Anthropic parser in `pensar.ts`, but consumes
 * Responses events (`response.output_text.delta`,
 * `response.function_call_arguments.delta`, `response.completed`, …) instead of
 * Anthropic Messages events. The Anthropic path is intentionally left untouched.
 */
export function parseResponsesSSE(
  sseStream: ReadableStream<Uint8Array>,
  options: ResponsesStreamOptions,
): ReadableStream<LanguageModelV3StreamPart> {
  const { abortSignal, idleTimeoutMs } = options;

  return new ReadableStream<LanguageModelV3StreamPart>({
    async start(controller) {
      let inputTokens = 0;
      let outputTokens = 0;
      let cacheReadTokens = 0;
      let noCacheInputTokens = 0;
      let finishReasonUnified: LanguageModelV3FinishReason["unified"] = "stop";
      let finishReasonRaw: string | undefined;
      let sawToolCall = false;

      // Lazily-opened text/reasoning blocks, keyed by Responses item/content id.
      const openText = new Set<string>();
      const openReasoning = new Set<string>();
      // Function calls keyed by Responses output-item id (the carrier of the
      // arguments delta stream), resolved to their stable call_id for AI-SDK.
      const toolsByItemId = new Map<string, PendingToolCall>();

      controller.enqueue({ type: "stream-start", warnings: [] });

      try {
        for await (const sse of parseSSE(sseStream, { idleTimeoutMs })) {
          if (sse.event === "pensar:usage") {
            continue;
          }

          let parsed: Record<string, unknown>;
          try {
            parsed = JSON.parse(sse.data);
          } catch {
            continue;
          }

          const type = (parsed.type as string) ?? sse.event;

          if (
            sse.event === "error" ||
            type === "error" ||
            type === "response.failed"
          ) {
            const message = extractErrorMessage(parsed);
            structuredLog.error(`Responses stream error: ${message}`);
            controller.error(new Error(message));
            return;
          }

          switch (type) {
            case "response.output_item.added": {
              const item = parsed.item as Record<string, unknown> | undefined;
              if (item?.type === "function_call") {
                const itemId = String(item.id ?? parsed.item_id ?? "");
                const callId = String(item.call_id ?? itemId);
                const name = String(item.name ?? "unknown");
                toolsByItemId.set(itemId, { callId, name, args: "" });
                controller.enqueue({
                  type: "tool-input-start",
                  id: callId,
                  toolName: name,
                });
              }
              break;
            }

            case "response.output_text.delta": {
              const id = textKey(parsed);
              if (!openText.has(id)) {
                controller.enqueue({ type: "text-start", id });
                openText.add(id);
              }
              controller.enqueue({
                type: "text-delta",
                id,
                delta: (parsed.delta as string) ?? "",
              });
              break;
            }

            case "response.output_text.done": {
              const id = textKey(parsed);
              if (openText.has(id)) {
                controller.enqueue({ type: "text-end", id });
                openText.delete(id);
              }
              break;
            }

            case "response.reasoning_summary_text.delta":
            case "response.reasoning_text.delta": {
              const id = reasoningKey(parsed);
              if (!openReasoning.has(id)) {
                controller.enqueue({ type: "reasoning-start", id });
                openReasoning.add(id);
              }
              controller.enqueue({
                type: "reasoning-delta",
                id,
                delta: (parsed.delta as string) ?? "",
              });
              break;
            }

            case "response.reasoning_summary_text.done":
            case "response.reasoning_text.done": {
              const id = reasoningKey(parsed);
              if (openReasoning.has(id)) {
                controller.enqueue({ type: "reasoning-end", id });
                openReasoning.delete(id);
              }
              break;
            }

            case "response.function_call_arguments.delta": {
              const itemId = String(parsed.item_id ?? "");
              const pending = toolsByItemId.get(itemId);
              if (pending) {
                const delta = (parsed.delta as string) ?? "";
                pending.args += delta;
                controller.enqueue({
                  type: "tool-input-delta",
                  id: pending.callId,
                  delta,
                });
              }
              break;
            }

            case "response.output_item.done": {
              const item = parsed.item as Record<string, unknown> | undefined;
              if (item?.type === "function_call") {
                const itemId = String(item.id ?? parsed.item_id ?? "");
                const pending = toolsByItemId.get(itemId);
                const callId =
                  pending?.callId ?? String(item.call_id ?? itemId);
                const name = pending?.name ?? String(item.name ?? "unknown");
                const args =
                  typeof item.arguments === "string"
                    ? item.arguments
                    : (pending?.args ?? "");
                controller.enqueue({ type: "tool-input-end", id: callId });
                controller.enqueue({
                  type: "tool-call",
                  toolCallId: callId,
                  toolName: name,
                  input: args,
                });
                sawToolCall = true;
                toolsByItemId.delete(itemId);
              } else {
                const reasoningId = reasoningKey(parsed);
                if (openReasoning.has(reasoningId)) {
                  controller.enqueue({
                    type: "reasoning-end",
                    id: reasoningId,
                  });
                  openReasoning.delete(reasoningId);
                }
              }
              break;
            }

            case "response.completed":
            case "response.incomplete": {
              const response = parsed.response as
                | Record<string, unknown>
                | undefined;
              const usage = response?.usage as
                | Record<string, unknown>
                | undefined;
              if (usage) {
                inputTokens = numberOf(usage.input_tokens);
                outputTokens = numberOf(usage.output_tokens);
                const details = usage.input_tokens_details as
                  | Record<string, unknown>
                  | undefined;
                cacheReadTokens = numberOf(details?.cached_tokens);
                noCacheInputTokens = Math.max(inputTokens - cacheReadTokens, 0);
              }
              const incomplete = response?.incomplete_details as
                | Record<string, unknown>
                | undefined;
              if (incomplete?.reason === "max_output_tokens") {
                finishReasonUnified = "length";
                finishReasonRaw = "max_output_tokens";
              } else if (sawToolCall) {
                finishReasonUnified = "tool-calls";
                finishReasonRaw = "tool_calls";
              } else {
                finishReasonUnified = "stop";
                finishReasonRaw = (response?.status as string) ?? "completed";
              }
              break;
            }
          }
        }

        // Close any blocks the upstream left open (defensive against truncated
        // streams) so the AI-SDK consumer always sees balanced start/end.
        for (const id of openText) {
          controller.enqueue({ type: "text-end", id });
        }
        for (const id of openReasoning) {
          controller.enqueue({ type: "reasoning-end", id });
        }

        controller.enqueue({
          type: "finish",
          finishReason: { unified: finishReasonUnified, raw: finishReasonRaw },
          usage: {
            inputTokens: {
              total: inputTokens,
              noCache: noCacheInputTokens || inputTokens,
              cacheRead: cacheReadTokens || undefined,
              cacheWrite: undefined,
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
        if (abortSignal?.aborted) {
          structuredLog.debug("Responses stream aborted by caller");
        }
        structuredLog.error(
          `Responses stream error: ${err instanceof Error ? err.message : String(err)}`,
          err instanceof Error ? err : undefined,
        );
        controller.error(err);
      }
    },
  });
}

function textKey(parsed: Record<string, unknown>): string {
  return `text-${parsed.item_id ?? "0"}-${parsed.content_index ?? 0}`;
}

function reasoningKey(parsed: Record<string, unknown>): string {
  const item = parsed.item as Record<string, unknown> | undefined;
  return `reasoning-${parsed.item_id ?? item?.id ?? "0"}`;
}

function numberOf(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function extractErrorMessage(parsed: Record<string, unknown>): string {
  const err = parsed.error;
  if (typeof err === "string") return err;
  if (err && typeof err === "object") {
    const message = (err as Record<string, unknown>).message;
    if (typeof message === "string") return message;
  }
  if (typeof parsed.message === "string") return parsed.message;
  return "Unknown Responses streaming error";
}

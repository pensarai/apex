import { AsyncLocalStorage } from "node:async_hooks";
import type { AnthropicMessagesModelId } from "@ai-sdk/anthropic/internal";
import type { OpenAIResponsesProviderOptions } from "@ai-sdk/openai";
import type { OpenAIChatModelId } from "@ai-sdk/openai/internal";
import {
  generateText,
  type LanguageModel,
  type ModelMessage,
  Output,
  type StopCondition,
  type StreamTextOnFinishCallback,
  type StreamTextOnStepFinishCallback,
  type StreamTextResult,
  streamText,
  type TextStreamPart,
  type ToolChoice,
  type ToolSet,
} from "ai";
import type { z } from "zod";
import { createLogger } from "../logger/structured";
import { shouldRecordAiPayloads } from "../observability";
import { scopedLogger } from "../util/lazyLogger";
import { withCachedLastMessage, withCachedSystemPrompt } from "./caching";
import { fitMessagesToContext, truncateWithMarker } from "./contextManagement";
import {
  getMaxOutputTokens,
  getModelInfo,
  prefersSequentialToolCalls,
} from "./models";
import { STREAM_DEBUG } from "./streamTelemetry";
import {
  type AIAuthConfig,
  checkIfContextLengthError,
  createSummarizationStream,
  getProviderModel,
  isAnthropicProvider,
} from "./utils";

const log = scopedLogger(() => createLogger("ai"));

// [response-debug] Mirror of offensiveSecurityAgent's tracer flag. Opt-in: set
// RESPONSE_DEBUG=1 (or "true") to surface it while debugging the empty-`{}` /
// looping response failure. When enabled these logs bypass the `silent` flag so
// they appear for silent threat-model sub-agents.
const RESPONSE_DEBUG =
  process.env.RESPONSE_DEBUG === "1" || process.env.RESPONSE_DEBUG === "true";
const RESPONSE_TOOL_NAME = "response";

export type AIModel = AnthropicMessagesModelId | OpenAIChatModelId | string; // For OpenRouter and Bedrock models

export type OpenAIReasoningEffort =
  | "none"
  | "low"
  | "medium"
  | "high"
  | "xhigh";

export const DEFAULT_OPENAI_REASONING_EFFORT: OpenAIReasoningEffort = "medium";

const OPENAI_REASONING_MODEL_IDS = new Set([
  "gpt-5",
  "gpt-5-2025-08-07",
  "gpt-5.1",
  "gpt-5.1-2025-11-13",
  "gpt-5.2",
  "gpt-5.2-2025-12-11",
  "gpt-5.2-pro",
  "gpt-5.2-pro-2025-12-11",
  "gpt-5.4",
  "gpt-5.4-2026-03-05",
  "gpt-5.4-pro",
  "gpt-5.4-pro-2026-03-05",
  "gpt-5.5",
  "gpt-5.5-2026-04-23",
]);

/**
 * Per-step billing context attached to a usage report.
 *
 * Carries the identity of the step that produced the usage so the billing
 * sink can attribute cost to a specific `(sessionId, stepSeq)` rather than a
 * whole run. Both fields are optional for backward compatibility — callers
 * that registered a 3-arg callback continue to work unchanged.
 */
export interface UsageStepContext {
  /** Session id (`ses_…`) that emitted the step, when known. */
  sessionId?: string;
  /** Monotonic per-run AI-SDK step index (see {@link runWithStepContext}). */
  stepSeq?: number;
}

/** Callback for reporting token usage from AI operations */
type UsageCallback = (
  model: string,
  inputTokens: number,
  outputTokens: number,
  ctx?: UsageStepContext,
) => void;
let _usageCallback: UsageCallback | null = null;

/** Register a callback to receive token usage reports from all AI operations */
export function onUsage(cb: UsageCallback | null): void {
  _usageCallback = cb;
}

// ---------------------------------------------------------------------------
// Per-run step counter (for per-step billing attribution)
// ---------------------------------------------------------------------------
//
// Each AI-SDK `streamText` step that reports usage is tagged with a monotonic
// `stepSeq` scoped to the emitting session. The counter lives in
// AsyncLocalStorage so concurrent runs (e.g. parallel subagents) never share
// or race a step index — each `runWithStepContext` call gets its own store.
//
// Monotonicity across a resumed run: the caller seeds `nextStepSeq` from the
// count of rehydrated assistant messages (the best available proxy for "how
// many steps already happened"). This guarantees monotonic-within-a-run and
// approximates cross-run monotonicity. It is NOT a strict global sequence —
// the authoritative per-session step ordering is the DB `stepSeq` on
// `agent_messages`; this counter only labels live usage reports for billing.

interface StepContext {
  sessionId?: string;
  /** Next step index to hand out; mutated in place as steps finish. */
  next: number;
}

const stepContextStore = new AsyncLocalStorage<StepContext>();

/**
 * Run `fn` within a per-run step-counting context. All `streamResponse` steps
 * executed inside `fn`'s async tree report usage tagged with `sessionId` and a
 * monotonically increasing `stepSeq` starting at `seedStepSeq` (default 0).
 *
 * Pass `seedStepSeq` = number of prior assistant messages on resume so the
 * counter continues past the rehydrated history.
 */
export function runWithStepContext<T>(
  opts: { sessionId?: string; seedStepSeq?: number },
  fn: () => T,
): T {
  return stepContextStore.run(
    { sessionId: opts.sessionId, next: opts.seedStepSeq ?? 0 },
    fn,
  );
}

/**
 * Take (and advance) the next `stepSeq` for the current run, returning the
 * accompanying billing context. Returns `undefined` when no step context is
 * active (e.g. one-off `generateText` calls outside a run) so callers stay
 * backward compatible.
 *
 * Exported for testing the per-step counter in isolation; production callers
 * should not need to call this directly.
 */
export function takeStepContext(): UsageStepContext | undefined {
  const store = stepContextStore.getStore();
  if (!store) return undefined;
  const stepSeq = store.next;
  store.next += 1;
  return { sessionId: store.sessionId, stepSeq };
}

export type AIModelProvider =
  | "anthropic"
  | "openai"
  | "google"
  | "openrouter"
  | "bedrock"
  | "pensar"
  | "inception"
  | "local";

/** Conservative default when `getModelInfo` doesn't have a `contextLength`. */
function getContextWindow(modelId: string): number {
  return getModelInfo(modelId).contextLength ?? 200_000;
}

function checkIfRateLimitError(error: unknown): boolean {
  const errObj =
    typeof error === "object" && error !== null
      ? (error as Record<string, unknown>)
      : {};

  // Check message — works for both Error instances and plain objects
  // (Bedrock streaming errors are plain { message: "..." } records)
  const errorMessage = (
    typeof errObj.message === "string" ? errObj.message : ""
  ).toLowerCase();
  const errorCode = String(
    typeof errObj.code === "string" ? errObj.code : "",
  ).toLowerCase();
  // AWS SDK errors surface the exception type via .name
  const errorName = (
    typeof errObj.name === "string" ? errObj.name : ""
  ).toLowerCase();
  // Bedrock HTTP-level errors include $metadata.httpStatusCode
  const httpStatus =
    typeof errObj.$metadata === "object" && errObj.$metadata !== null
      ? (errObj.$metadata as Record<string, unknown>).httpStatusCode
      : undefined;
  // Stringified fallback for opaque error objects (e.g. Bedrock stream records)
  const errorString =
    errorMessage || errorName ? "" : String(error).toLowerCase();

  return (
    // Message-based detection
    errorMessage.includes("too many tokens") ||
    errorMessage.includes("rate limit") ||
    errorMessage.includes("request rate") ||
    errorMessage.includes("throttl") ||
    errorMessage.includes("overloaded") ||
    errorMessage.includes("too many requests") ||
    errorMessage.includes("please wait") ||
    errorMessage.includes("service unavailable") ||
    // AWS SDK exception names (ThrottlingException, TooManyRequestsException)
    errorName.includes("throttl") ||
    errorName.includes("toomanyrequests") ||
    errorName.includes("serviceunavailable") ||
    // Error codes
    errorCode === "rate_limit_exceeded" ||
    errorCode === "throttling" ||
    errorCode === "429" ||
    // HTTP status from AWS SDK $metadata
    httpStatus === 429 ||
    httpStatus === 529 ||
    httpStatus === 503 ||
    // Fallback: stringified error for opaque Bedrock stream records
    errorString.includes("throttl") ||
    errorString.includes("too many") ||
    errorString.includes("request rate")
  );
}

// Injected into the system prompt for models that mis-parse parallel tool
// calls (DeepSeek V3.1 on Bedrock). See prefersSequentialToolCalls.
const SEQUENTIAL_TOOL_CALL_INSTRUCTION =
  "CRITICAL TOOL-CALLING RULE: Emit EXACTLY ONE tool call per response. " +
  "Never emit more than one tool call in a single turn. After each tool call, " +
  "wait for its result before making the next one. Emitting multiple tool " +
  "calls in one turn corrupts their arguments.";

// Returns the system prompt that is actually sent to the provider, accounting
// for the sequential-tool-call policy appended for models that mis-parse
// parallel tool calls. Token budgeting (`fitMessagesToContext`) must use this
// value, not the raw `system`, or it underestimates the system prompt size and
// overestimates the message budget near the context limit.
function applySequentialToolCallPolicy(
  system: string | undefined,
  tools: ToolSet | undefined,
  model: AIModel,
): string | undefined {
  if (
    tools &&
    Object.keys(tools).length > 0 &&
    prefersSequentialToolCalls(model)
  ) {
    return `${system ? `${system}\n\n` : ""}${SEQUENTIAL_TOOL_CALL_INSTRUCTION}`;
  }
  return system;
}

const MAX_RATE_LIMIT_RETRIES = 20;
const MAX_IDLE_RESUME_RETRIES = 3;
const STREAM_IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

class StreamIdleTimeoutError extends Error {
  constructor(idleMs: number) {
    super(`Stream idle for ${Math.round(idleMs / 1000)}s — no chunks received`);
    this.name = "StreamIdleTimeoutError";
  }
}

/**
 * Wraps an async iterable with a per-chunk idle timeout. If no chunk arrives
 * within `idleMs`, throws a {@link StreamIdleTimeoutError} so the caller can
 * resume the conversation from accumulated messages.
 *
 * @param isIdleTimerActive Optional predicate evaluated before awaiting each
 *   chunk. When it returns `false` the timer is skipped for that chunk and we
 *   wait indefinitely. This lets callers suppress the timeout during expected
 *   long pauses (e.g. while a tool call is executing) so a slow tool isn't
 *   misread as a stalled provider stream.
 */
async function* withIdleTimeout<T>(
  stream: AsyncIterable<T>,
  idleMs: number,
  isIdleTimerActive?: () => boolean,
): AsyncGenerator<T> {
  const iterator = stream[Symbol.asyncIterator]();
  try {
    while (true) {
      const timerActive = isIdleTimerActive?.() ?? true;
      let result: IteratorResult<T>;
      if (timerActive) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        result = await Promise.race([
          iterator.next(),
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(new StreamIdleTimeoutError(idleMs)),
              idleMs,
            );
            if (typeof timer === "object" && "unref" in timer) timer.unref();
          }),
        ]);
        clearTimeout(timer);
      } else {
        result = await iterator.next();
      }

      if (result.done) return;
      yield result.value;
    }
  } finally {
    // Best-effort cleanup — don't block on a stuck iterator. The underlying
    // stream may be wedged (that's why we're here), so a hanging return()
    // would deadlock the consumer.
    iterator.return?.()?.catch?.(() => {});
  }
}

function isStreamIdleTimeoutError(error: unknown): boolean {
  // The chunk-level StreamIdleTimeoutError, which the AI SDK may rewrap — so
  // walk `cause`.
  for (let e: unknown = error, depth = 0; e != null && depth < 6; depth++) {
    if (e instanceof StreamIdleTimeoutError) return true;
    e = (e as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * Gates the idle-timeout in {@link withIdleTimeout} so it only fires while
 * we're waiting on the **model**, not while a tool is executing.
 *
 * The provider stream emits nothing between a `tool-call` chunk and the
 * matching `tool-result`. A slow tool (e.g. `run_attack_surface`, which
 * spawns a multi-minute sub-agent) would otherwise be misread as a stalled
 * stream — triggering the auto-resume path and causing the model to re-issue
 * the same tool call, which spawns a duplicate sub-agent.
 *
 * Parallel tool calls are tracked by `toolCallId`. Duplicate `tool-call`
 * chunks for the same id (defensive — should never happen in practice) are
 * deduplicated. `tool-result` chunks without a matching open call are
 * ignored so the counter can never go negative.
 *
 * EXCEPTION — the structured `response` tool is NEVER counted as in-flight. Its
 * `execute` only captures the result and returns synchronously (it does no real
 * work), so it can't be a slow tool the gate needs to wait out. But the model
 * streams that tool's arguments — frequently a multi-thousand-token structured
 * payload — and a provider (Bedrock) stream that WEDGES mid-payload would, if
 * `response` were gated, suppress the idle timeout forever (a confirmed hang:
 * threat-model children frozen on `response` for 10+ min, never recovered).
 * Leaving `response` ungated keeps the idle timer live across its generation,
 * so a stalled response stream trips the normal idle-timeout → auto-resume path.
 */
const NON_GATED_TOOLS = new Set<string>(["response"]);

function createToolExecutionGate(): {
  shouldEnforceIdleTimeout: () => boolean;
  observe: (chunk: {
    type: string;
    toolCallId?: string;
    toolName?: string;
  }) => void;
} {
  let inFlight = 0;
  const open = new Set<string>();

  return {
    shouldEnforceIdleTimeout: () => inFlight === 0,
    observe: (chunk) => {
      if (chunk.type === "tool-call") {
        if (chunk.toolName && NON_GATED_TOOLS.has(chunk.toolName)) return;
        const id = chunk.toolCallId;
        if (id) {
          if (!open.has(id)) {
            open.add(id);
            inFlight++;
          }
        } else {
          inFlight++;
        }
      } else if (chunk.type === "tool-result") {
        const id = chunk.toolCallId;
        if (id) {
          if (open.delete(id)) {
            inFlight = Math.max(0, inFlight - 1);
          }
        } else if (!(chunk.toolName && NON_GATED_TOOLS.has(chunk.toolName))) {
          inFlight = Math.max(0, inFlight - 1);
        }
      }
    },
  };
}

// Helper function to wrap a stream with error handling for async errors
function wrapStreamWithErrorHandler(
  originalStream: StreamTextResult<ToolSet, never>,
  messagesContainer: { current: ModelMessage[] },
  opts: StreamResponseOpts,
  model: LanguageModel,
  silent?: boolean,
  rateLimitRetryCount: number = 0,
  idleResumeCount: number = 0,
): StreamTextResult<ToolSet, never> {
  // Create a lazy getter for fullStream that wraps it with error handling
  let wrappedStream: AsyncIterable<TextStreamPart<ToolSet>> | null = null;

  const handler = {
    get(_target: StreamTextResult<ToolSet, never>, prop: string | symbol) {
      // Intercept access to fullStream
      if (prop === "fullStream") {
        if (!wrappedStream) {
          // Tool-execution gate: keeps the idle timer paused while a tool
          // is in flight (see {@link createToolExecutionGate}). The gate's
          // predicate is read by `withIdleTimeout` at the top of each
          // iteration — which always runs AFTER the previous chunk's body
          // finished mutating the gate, so observations are always visible
          // before the next idle-race begins.
          const toolGate = createToolExecutionGate();

          wrappedStream = (async function* () {
            try {
              for await (const chunk of withIdleTimeout(
                originalStream.fullStream,
                STREAM_IDLE_TIMEOUT_MS,
                toolGate.shouldEnforceIdleTimeout,
              )) {
                toolGate.observe(chunk);

                // [response-debug] Log the AI-SDK-level view of the response
                // tool lifecycle as chunks leave the transport wrapper. This is
                // the layer BELOW the consume() loop — it reveals whether the SDK
                // emitted a terminal tool-call/tool-error for response, and the
                // per-step finishReason that decides whether the loop continues.
                if (RESPONSE_DEBUG) {
                  const c = chunk as {
                    type: string;
                    toolName?: string;
                    toolCallId?: string;
                    finishReason?: string;
                    invalid?: boolean;
                  };
                  if (
                    (c.type === "tool-call" ||
                      c.type === "tool-error" ||
                      c.type === "tool-result") &&
                    c.toolName === RESPONSE_TOOL_NAME
                  ) {
                    log.warn(
                      `[response-debug] ai-layer chunk=${c.type} response id=${c.toolCallId} invalid=${c.invalid === true}`,
                    );
                  } else if (c.type === "finish-step") {
                    log.warn(
                      `[response-debug] ai-layer finish-step finishReason=${c.finishReason}`,
                    );
                  }
                }

                // Only stream-level errors are fatal; tool-level errors
                // flow through so the UI renders them as failed tool results.
                if (chunk.type === "error") {
                  throw (chunk as unknown as { error: unknown }).error;
                }

                yield chunk;
              }
            } catch (error) {
              const errorMessage =
                error instanceof Error ? error.message : String(error);

              // Check context length FIRST — these should never be retried
              // as-is; the prompt must be reduced via summarization.
              const isCtxError = checkIfContextLengthError(error);

              // Handle stream idle timeout — resume from accumulated messages
              if (
                !isCtxError &&
                isStreamIdleTimeoutError(error) &&
                idleResumeCount < MAX_IDLE_RESUME_RETRIES &&
                messagesContainer.current.length > 0
              ) {
                const nextIdleCount = idleResumeCount + 1;
                // Surfaced on silent sub-agents too when stream-debugging.
                if (!silent || STREAM_DEBUG) {
                  log.warn(
                    `Stream stalled (attempt ${nextIdleCount}/${MAX_IDLE_RESUME_RETRIES}), resuming with ${messagesContainer.current.length} messages: ${errorMessage}`,
                  );
                }

                const retriedStream = streamResponse({
                  ...opts,
                  messages: messagesContainer.current,
                });

                const wrappedRetriedStream = wrapStreamWithErrorHandler(
                  retriedStream,
                  messagesContainer,
                  opts,
                  model,
                  silent,
                  rateLimitRetryCount,
                  nextIdleCount,
                );

                for await (const chunk of wrappedRetriedStream.fullStream) {
                  yield chunk;
                }
                return;
              }

              // Handle rate limit errors with exponential backoff retry
              if (
                !isCtxError &&
                checkIfRateLimitError(error) &&
                rateLimitRetryCount < MAX_RATE_LIMIT_RETRIES
              ) {
                const nextRetryCount = rateLimitRetryCount + 1;
                const delayMs = Math.min(1000 * nextRetryCount, 30000);

                if (!silent) {
                  log.warn(
                    `Rate limit error (attempt ${nextRetryCount}/${MAX_RATE_LIMIT_RETRIES}), waiting ${delayMs}ms: ${errorMessage}`,
                  );
                }

                await new Promise((resolve) => setTimeout(resolve, delayMs));

                const retriedStream = streamResponse({
                  ...opts,
                  messages:
                    messagesContainer.current.length > 0
                      ? messagesContainer.current
                      : undefined,
                });

                const wrappedRetriedStream = wrapStreamWithErrorHandler(
                  retriedStream,
                  messagesContainer,
                  opts,
                  model,
                  silent,
                  nextRetryCount,
                  idleResumeCount,
                );

                for await (const chunk of wrappedRetriedStream.fullStream) {
                  yield chunk;
                }
                return;
              }

              if (isCtxError) {
                let currentMessages: ModelMessage[] = messagesContainer.current;
                try {
                  const response = await originalStream.response;
                  if (response.messages && response.messages.length > 0) {
                    currentMessages = response.messages as ModelMessage[];
                  }
                } catch {
                  // Fall back to container messages.
                }

                const fitted = fitMessagesToContext(currentMessages, {
                  contextWindow: getContextWindow(opts.model),
                  maxOutputTokens: getMaxOutputTokens(opts.model),
                  system: applySequentialToolCallPolicy(
                    opts.system,
                    opts.tools,
                    opts.model,
                  ),
                  tools: opts.tools,
                  sessionPath: opts.sessionPath,
                });

                messagesContainer.current = fitted.messages;

                // Track depth across the reactive paths so that a failed
                // Layer 1+2 retry CONTRIBUTES to the Layer 3 budget too.
                // Without this, a failed retry's increment is "lost" on
                // fall-through (Layer 3 reads outer `opts._restartDepth`,
                // not the post-retry value) and recovery can burn close
                // to double the intended provider calls before
                // `MAX_RESTART_DEPTH` finally trips.
                let postReactiveDepth = opts._restartDepth ?? 0;

                if (fitted.fitsBudget && fitted.modified) {
                  if (!silent) {
                    log.warn(
                      `Context length error — Layer 1+2 reduced to ~${fitted.estimatedInputTokens} tokens, retrying`,
                    );
                  }
                  try {
                    // Bump `_restartDepth` so a tokenizer-drift loop where
                    // every reactive retry trips the same provider rejection
                    // (fitsBudget=true by our estimator, still rejected by
                    // the provider) eventually exhausts the depth bound at
                    // the top of `streamResponse` instead of looping
                    // forever. Without this, only Layer-3 escalation
                    // increments depth and a drift-driven loop can burn
                    // arbitrarily many failed provider calls.
                    const retried = streamResponse({
                      ...opts,
                      messages: fitted.messages,
                      _restartDepth: postReactiveDepth + 1,
                    });
                    const wrappedRetry = wrapStreamWithErrorHandler(
                      retried,
                      messagesContainer,
                      opts,
                      model,
                      silent,
                      rateLimitRetryCount,
                      idleResumeCount,
                    );
                    for await (const chunk of wrappedRetry.fullStream) {
                      yield chunk;
                    }
                    return;
                  } catch (retryError) {
                    // Always propagate the typed terminal error and
                    // cancellations — these MUST escape the cascade
                    // immediately. Currently `ContextLengthExhaustedError`
                    // propagates only by accident (its message
                    // "Context-length recovery exhausted…" uses a hyphen
                    // that doesn't match any `checkIfContextLengthError`
                    // pattern); the explicit `instanceof` and abort
                    // checks are defensive against a future message-text
                    // tweak that would otherwise silently swallow
                    // recovery exhaustion. Mirrors the Layer 3
                    // `summarizeError` catch below for symmetry.
                    if (
                      retryError instanceof ContextLengthExhaustedError ||
                      (retryError instanceof Error &&
                        retryError.name === "AbortError") ||
                      opts.abortSignal?.aborted ||
                      !checkIfContextLengthError(retryError)
                    ) {
                      throw retryError;
                    }
                    // Account for the depth slot the failed retry just
                    // consumed so the Layer 3 paths below don't grant a
                    // fresh budget on top of the already-spent cycle.
                    postReactiveDepth += 1;
                  }
                }

                // Layer 3: full summarization. Wrapped because
                // `summarizeConversation` itself calls `generateText` and
                // can throw — fall back to a minimal-context restart.
                const messagesForSummary = messagesContainer.current;
                if (!silent) {
                  log.warn(
                    `Context length error — summarizing ${messagesForSummary.length} messages`,
                  );
                }

                try {
                  const summarizationStream = createSummarizationStream(
                    messagesForSummary,
                    { ...opts, _restartDepth: postReactiveDepth },
                    model,
                  );
                  for await (const chunk of summarizationStream.fullStream) {
                    yield chunk;
                  }
                } catch (summarizeError) {
                  // Only fall through to minimal-restart for context-length
                  // errors. For everything else — auth failures, network
                  // errors, abort signals, the typed terminal
                  // `ContextLengthExhaustedError`, or non-`Error` throws —
                  // propagate immediately. Without this, an aborted call
                  // would spawn a new provider request, and a transient
                  // auth failure would burn an extra cycle that fails
                  // identically.
                  if (
                    summarizeError instanceof ContextLengthExhaustedError ||
                    (summarizeError instanceof Error &&
                      summarizeError.name === "AbortError") ||
                    opts.abortSignal?.aborted ||
                    !checkIfContextLengthError(summarizeError)
                  ) {
                    throw summarizeError;
                  }
                  if (!silent) {
                    const sumMsg =
                      summarizeError instanceof Error
                        ? summarizeError.message
                        : String(summarizeError);
                    log.warn(
                      `Layer 3 summarization failed (${sumMsg}). Falling back to minimal-context restart.`,
                    );
                  }
                  opts.onSummarized?.("");
                  const minimalPrompt =
                    typeof opts.prompt === "string" && opts.prompt.length > 0
                      ? opts.prompt.slice(0, 4_000)
                      : MINIMAL_RESTART_PROMPT;
                  const fallback = streamResponse({
                    ...opts,
                    prompt: minimalPrompt,
                    messages: undefined,
                    _restartDepth: postReactiveDepth + 1,
                  });
                  for await (const chunk of fallback.fullStream) {
                    yield chunk;
                  }
                }
              } else {
                if (!silent) {
                  log.error("Non-recoverable stream error, re-throwing", {
                    error: errorMessage,
                  });
                }
                throw error;
              }
            }
          })();
        }
        return wrappedStream;
      }

      // For all other properties, return the original
      return (originalStream as unknown as Record<string | symbol, unknown>)[
        prop
      ];
    },
  };

  return new Proxy(originalStream, handler);
}

// Available models with names
export interface ModelInfo {
  id: AIModel;
  name: string;
  provider: AIModelProvider;
  contextLength?: number;
}

/**
 * Check whether a model supports extended thinking based on its ID.
 *
 * Thinking is available on Claude 3.7 Sonnet and all Claude 4.x+ models
 * (Sonnet, Opus, Haiku 4.5). Works for Anthropic direct, Bedrock, and
 * Pensar provider IDs.
 */
export function modelSupportsThinking(modelId: string): boolean {
  // Normalize: strip provider prefixes so we match the base Claude model ID
  const normalized = modelId
    .replace(/^pensar:/, "")
    .replace(/^(us\.|eu\.|global\.|ap\.)?anthropic\./, "");

  return (
    /^claude-3-7-sonnet/.test(normalized) ||
    /^claude-sonnet-4/.test(normalized) ||
    /^claude-opus-4/.test(normalized) ||
    /^claude-haiku-4-5/.test(normalized)
  );
}

export function modelSupportsOpenAIReasoning(modelId: string): boolean {
  const { provider } = getModelInfo(modelId);
  if (provider !== "openai") return false;
  return (
    OPENAI_REASONING_MODEL_IDS.has(modelId) || /^o[134](?:\b|-)/.test(modelId)
  );
}

export function getOpenAIReasoningEfforts(
  modelId: string,
): OpenAIReasoningEffort[] {
  if (!modelSupportsOpenAIReasoning(modelId)) return [];
  if (/^gpt-5\.5(?:\b|-)/.test(modelId)) {
    return ["none", "low", "medium", "high", "xhigh"];
  }
  return ["low", "medium", "high"];
}

export function normalizeOpenAIReasoningEffort(
  modelId: string,
  effort?: OpenAIReasoningEffort | null,
): OpenAIReasoningEffort | undefined {
  const efforts = getOpenAIReasoningEfforts(modelId);
  if (efforts.length === 0) return undefined;
  if (effort && efforts.includes(effort)) return effort;
  return DEFAULT_OPENAI_REASONING_EFFORT;
}

/** Cache token metrics extracted from Anthropic providerMetadata */
export interface CacheMetrics {
  cacheReadInputTokens: number;
  cacheCreationInputTokens: number;
}

export interface StreamResponseOpts {
  prompt: string;
  system?: string;
  model: AIModel;
  messages?: Array<ModelMessage>;
  stopWhen?:
    | StopCondition<NoInfer<ToolSet>>
    | StopCondition<NoInfer<ToolSet>>[];
  toolChoice?: ToolChoice<ToolSet>;
  tools?: ToolSet;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  abortSignal?: AbortSignal;
  activeTools?: string[];
  silent?: boolean;
  authConfig?: AIAuthConfig;
  onFinish?: StreamTextOnFinishCallback<ToolSet>;
  /**
   * Called when the context window overflows and the conversation is
   * summarized. Callers should use this to discard stale message history
   * so that subsequent persistence writes only include the summary +
   * new messages (not the full pre-summarization history).
   */
  onSummarized?: (summary: string) => void;
  /** Called when Anthropic cache metrics are present in a step's providerMetadata */
  onCacheMetrics?: (metrics: CacheMetrics) => void;
  /** Enable extended thinking for supported models (Anthropic Claude 3.7+) */
  enableThinking?: boolean;
  /** OpenAI reasoning effort for GPT/o-series reasoning models. */
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  /** Session root path — used by context management layers to persist truncated tool results */
  sessionPath?: string;
  /**
   * Session id (`ses_…`) of the agent making this call — the root session for
   * the root agent, or the subagent's own session. Stamped onto AI-span
   * telemetry so traces are filterable by session. Forwarded unchanged through
   * the internal retry/resume recursion via `...opts`.
   */
  sessionId?: string;
  /**
   * Internal: recovery-recursion depth. Bumped at each summarize → resume
   * boundary; throws `ContextLengthExhaustedError` past `MAX_RESTART_DEPTH`.
   */
  _restartDepth?: number;
}

export function streamResponse(
  opts: StreamResponseOpts,
): StreamTextResult<ToolSet, never> {
  // Bound recovery recursion (summarize → resume → overflow → …).
  const restartDepth = opts._restartDepth ?? 0;
  if (restartDepth > MAX_RESTART_DEPTH) {
    throw new ContextLengthExhaustedError(
      `Context-length recovery exhausted after ${restartDepth} restart cycles`,
      restartDepth,
    );
  }

  const {
    prompt,
    system,
    model,
    messages,
    stopWhen,
    toolChoice,
    tools,
    onStepFinish: userOnStepFinish,
    abortSignal,
    activeTools,
    silent,
    authConfig,
    onFinish,
    onCacheMetrics,
    enableThinking,
    openAIReasoningEffort,
    sessionId,
  } = opts;

  // Wrap onStepFinish to fire usage callback for every step.
  // Must be async so that callers returning a Promise (e.g. persistence /
  // issue queuing) are fully awaited before the AI SDK starts the next step.
  const onStepFinish: typeof userOnStepFinish = async (step) => {
    await userOnStepFinish?.(step);
    if (_usageCallback) {
      const inp = step.usage?.inputTokens ?? 0;
      const out = step.usage?.outputTokens ?? 0;
      // Always advance the step counter once per finished step (even with zero
      // usage) so `stepSeq` stays aligned with the AI-SDK step index.
      const stepCtx = takeStepContext();
      if (inp > 0 || out > 0) _usageCallback(model, inp, out, stepCtx);
    }
  };
  const providerModel = getProviderModel(model, authConfig);
  const useAnthropicCaching = isAnthropicProvider(model);

  // Models that mis-parse multiple tool calls per turn (DeepSeek V3.1 on
  // Bedrock) are constrained to one tool call per turn via system prompt —
  // single calls parse correctly, parallel calls drop/empty arguments. Only
  // applied when tools are actually bound. See prefersSequentialToolCalls.
  // Computed before context fitting so token budgeting accounts for the
  // appended instruction that is actually sent to the provider.
  const systemWithToolPolicy = applySequentialToolCallPolicy(
    system,
    tools,
    model,
  );

  // Proactive context fit: compact before the call. Reactive recovery
  // below is a safety net for tokenizer drift the estimate doesn't catch.
  let fittedMessages = messages;
  let proactiveFitFailed = false;
  if (messages && messages.length > 0) {
    const fitted = fitMessagesToContext(messages, {
      contextWindow: getContextWindow(model),
      maxOutputTokens: getMaxOutputTokens(model),
      system: systemWithToolPolicy,
      tools,
      sessionPath: opts.sessionPath,
    });
    fittedMessages = fitted.messages;
    proactiveFitFailed = !fitted.fitsBudget;
    if (fitted.modified && !silent) {
      log.warn(
        `Proactive context fit: compacted messages to ~${fitted.estimatedInputTokens} tokens (fits=${fitted.fitsBudget})`,
      );
    }
  }

  // Container reference is stable; value gets reassigned by `prepareStep`
  // and the recovery paths so nested retries read the latest compacted view.
  const messagesContainer = { current: fittedMessages || [] };

  // Layer 1+2 alone can't fit — escalate before sending a doomed request.
  // Wrap with the same error handler the streamText path uses, otherwise
  // an overflow inside the summarization call itself escapes uncaught while
  // the equivalent post-streamText path (line ~880) recovers.
  if (proactiveFitFailed && fittedMessages) {
    if (!silent) {
      log.warn(
        `Proactive context fit returned fitsBudget=false on ${fittedMessages.length} messages — escalating to summarization before send`,
      );
    }
    // Pass `opts` through unchanged. The slot for this escalation is
    // consumed by `summarizeConversation`'s internal `_restartDepth + 1`
    // bump on the resumed `streamResponse` call — pre-bumping here would
    // double-count vs the reactive Layer 3 path (which also passes
    // `opts._restartDepth` to `createSummarizationStream` after a
    // no-retry fall-through). With the post-bump, all three escalation
    // entry points (proactive, outer-catch, reactive Layer 3) consume
    // exactly one depth slot per summarization attempt — symmetric.
    return wrapStreamWithErrorHandler(
      createSummarizationStream(fittedMessages, opts, providerModel),
      messagesContainer,
      opts,
      providerModel,
      silent,
    );
  }

  // For Anthropic models, move the system prompt into messages with cache_control.
  // This caches tools + system prompt across multi-turn conversations (~90% cost reduction on cache hits).
  let effectiveSystem: string | undefined = systemWithToolPolicy;
  let effectiveMessages: ModelMessage[] | undefined = fittedMessages;

  if (useAnthropicCaching && systemWithToolPolicy) {
    const baseMessages: ModelMessage[] = fittedMessages ?? [
      { role: "user" as const, content: prompt },
    ];
    effectiveMessages = withCachedSystemPrompt(
      systemWithToolPolicy,
      baseMessages,
    );
    effectiveSystem = undefined;
  }

  // Build providerOptions for extended thinking when enabled on a supported model.
  // Caching uses message-level cache_control (withCachedSystemPrompt / withCachedLastMessage),
  // not providerOptions, so there is no collision.
  // Note: when thinking is enabled, temperature must not be set (Anthropic rejects it).
  const useThinking =
    enableThinking &&
    isAnthropicProvider(model) &&
    modelSupportsThinking(model);
  const normalizedOpenAIEffort = normalizeOpenAIReasoningEffort(
    model,
    openAIReasoningEffort,
  );
  const providerOptions:
    | {
        anthropic?: {
          thinking: {
            type: "adaptive";
          };
        };
        openai?: OpenAIResponsesProviderOptions;
      }
    | undefined =
    useThinking || normalizedOpenAIEffort
      ? {
          ...(useThinking
            ? {
                anthropic: {
                  thinking: {
                    type: "adaptive" as const,
                  },
                },
              }
            : {}),
          ...(normalizedOpenAIEffort
            ? {
                openai: {
                  reasoningEffort: normalizedOpenAIEffort,
                },
              }
            : {}),
        }
      : undefined;

  let rateLimitRetryCount = 0;

  try {
    // Create the appropriate provider instance
    const recordPayloads = shouldRecordAiPayloads();
    const response = streamText({
      model: providerModel,
      system: effectiveSystem,
      ...(effectiveMessages ? { messages: effectiveMessages } : { prompt }),
      stopWhen,
      toolChoice,
      tools,
      maxRetries: 3,
      providerOptions,
      experimental_telemetry: {
        isEnabled: true,
        recordInputs: recordPayloads,
        recordOutputs: recordPayloads,
        functionId: `apex.stream.${model}`,
        ...(sessionId ? { metadata: { sessionId } } : {}),
      },
      // Pin actual emission to the same value `fitMessagesToContext`
      // reserved for output. Without this, the SDK applies provider
      // defaults that can exceed our budget — e.g. GPT-4o defaults to
      // 16K output but our messages were sized assuming a smaller
      // reservation. Making the value explicit closes that drift class.
      maxOutputTokens: getMaxOutputTokens(model),
      prepareStep: (opts) => {
        // Update the container with the latest messages
        messagesContainer.current = opts.messages;
        // For Anthropic, add cache_control to the last message for incremental caching
        if (useAnthropicCaching) {
          return { messages: withCachedLastMessage(opts.messages) };
        }
        return undefined;
      },
      onError: async ({ error }: { error: unknown }) => {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        if (
          errorMessage.toLowerCase().includes("too many tokens") ||
          errorMessage.toLowerCase().includes("overloaded")
        ) {
          rateLimitRetryCount++;
          await new Promise((resolve) =>
            setTimeout(resolve, 1000 * rateLimitRetryCount),
          );
          if (rateLimitRetryCount < 20) {
            return;
          }
        }
        throw error;
      },
      onStepFinish: onCacheMetrics
        ? (stepResult) => {
            // Extract Anthropic cache metrics from providerMetadata (direct Anthropic / Bedrock SDK)
            const meta = stepResult.providerMetadata?.anthropic as
              | Record<string, unknown>
              | undefined;
            let cacheRead = (meta?.cacheReadInputTokens as number) ?? 0;
            let cacheCreation = (meta?.cacheCreationInputTokens as number) ?? 0;

            // Pensar provider doesn't populate providerMetadata.anthropic;
            // fall back to the SDK's normalized usage.inputTokenDetails.
            if (cacheRead === 0 && cacheCreation === 0) {
              const { inputTokenDetails } = stepResult.usage;
              cacheRead = inputTokenDetails?.cacheReadTokens ?? 0;
              cacheCreation = inputTokenDetails?.cacheWriteTokens ?? 0;
            }

            if (cacheRead > 0 || cacheCreation > 0) {
              onCacheMetrics({
                cacheReadInputTokens: cacheRead,
                cacheCreationInputTokens: cacheCreation,
              });
            }
            onStepFinish?.(stepResult);
          }
        : onStepFinish,
      abortSignal,
      activeTools,
      experimental_repairToolCall: async ({
        toolCall,
        inputSchema,
        tools,
        error,
      }) => {
        // [response-debug] Always log (bypassing `silent`) when repair fires for
        // the `response` tool — repair firing means the streamed args FAILED Zod
        // validation. If we never see this for a looping session, the args were
        // never finalized into a tool-call chunk at all (truncated mid-stream).
        if (RESPONSE_DEBUG && toolCall.toolName === RESPONSE_TOOL_NAME) {
          const raw = toolCall.input;
          const rawLen =
            typeof raw === "string" ? raw.length : JSON.stringify(raw).length;
          log.warn(
            `[response-debug] experimental_repairToolCall FIRED for response ` +
              `rawInputChars=${rawLen} error=${(error.message || String(error)).slice(0, 200)}`,
          );
        }
        try {
          if (!silent) {
            log.debug(`Repairing tool call: ${toolCall.toolName}`, {
              error: error.message || String(error),
            });

            // Log specific details for common enum errors
            if (
              error.message &&
              (error.message.includes("severity") ||
                error.message.includes("riskLevel"))
            ) {
              log.debug(
                "Enum validation error — tool call repair will normalize the value",
              );
            }
          }

          // Get the actual tool definition which contains the Zod schema
          const tool = tools[toolCall.toolName];
          if (!tool?.inputSchema) {
            if (!silent) {
              log.warn(
                `Cannot repair tool call: ${toolCall.toolName} not found or has no schema`,
              );
            }
            return null;
          }

          const jsonSchema = inputSchema({ toolName: toolCall.toolName });

          // Bound input + schema so the repair call can't itself overflow.
          const rawInput = toolCall.input;
          const inputAsText =
            typeof rawInput === "string" ? rawInput : JSON.stringify(rawInput);
          const boundedInput = truncateWithMarker(
            inputAsText,
            MAX_TOOL_INPUT_CHARS,
          );
          const boundedSchema = truncateWithMarker(
            JSON.stringify(jsonSchema),
            MAX_SCHEMA_CHARS,
            "schema",
          );

          const { output: repairedArgs, usage: repairUsage } =
            await generateText({
              model: providerModel,
              output: Output.object({
                schema: tool.inputSchema, // Use the actual Zod schema from the tool
              }),
              prompt: [
                `The model tried to call the tool "${toolCall.toolName}"` +
                  ` with the following inputs:`,
                boundedInput,
                `The tool accepts the following schema:`,
                boundedSchema,
                `Error encountered: ${error}`,
                "Please fix the inputs to match the schema.",
                "",
                "IMPORTANT: For enum fields like 'severity' or 'riskLevel', use ONLY the exact values from the enum (e.g., 'HIGH', 'CRITICAL', 'MEDIUM', 'LOW').",
                "Do not add prefixes, suffixes, or formatting characters like '>', '-', '!', etc.",
              ].join("\n"),
              abortSignal,
              experimental_telemetry: {
                isEnabled: true,
                recordInputs: recordPayloads,
                recordOutputs: recordPayloads,
                functionId: "apex.tool_repair",
                ...(sessionId ? { metadata: { sessionId } } : {}),
              },
            });

          // Report tool repair token usage if onStepFinish callback is provided
          if (onStepFinish && repairUsage) {
            onStepFinish({
              text: "",
              reasoning: undefined,
              reasoningDetails: [],
              files: [],
              sources: [],
              toolCalls: [],
              toolResults: [],
              finishReason: "stop",
              usage: {
                inputTokens: repairUsage.inputTokens ?? 0,
                outputTokens: repairUsage.outputTokens ?? 0,
                totalTokens: repairUsage.totalTokens ?? 0,
              },
              warnings: [],
              request: {},
              response: {
                id: "tool-repair",
                timestamp: new Date(),
                modelId: "",
                messages: [],
              },
              providerMetadata: undefined,
              stepType: "initial",
              isContinued: false,
            } as unknown as Parameters<
              StreamTextOnStepFinishCallback<ToolSet>
            >[0]);
          }

          if (repairedArgs === undefined || repairedArgs === null) {
            if (!silent) {
              log.warn(
                `Tool call repair for "${toolCall.toolName}" produced no valid output`,
              );
            }
            return null;
          }
          return { ...toolCall, input: JSON.stringify(repairedArgs) };
        } catch (repairError) {
          if (!silent) {
            log.warn("Error repairing tool call", {
              error: String(repairError),
            });
          }
          return null;
        }
      },
      onFinish,
    });

    // Wrap the stream to catch async errors during consumption
    return wrapStreamWithErrorHandler(
      response,
      messagesContainer,
      opts,
      providerModel,
      silent,
    );
  } catch (error) {
    // Check if the error is related to context length
    const isContextLengthError = checkIfContextLengthError(error);
    const outerErrorMessage =
      error instanceof Error ? error.message : String(error);

    if (isContextLengthError) {
      if (!silent) {
        log.warn(
          `Context length error, summarizing ${messagesContainer.current.length} messages`,
          { error: outerErrorMessage },
        );
      }
      // Wrap so a context error inside the summarization stream itself
      // (or the resumed `streamResponse` it triggers) is caught and routed
      // through the same recovery cascade as the proactive and reactive
      // paths — invariant I4: every context-recovery failure must be caught
      // at the `streamResponse` boundary, never escape raw to the consumer.
      //
      // Pass `opts` through unchanged — the slot is consumed by
      // `summarizeConversation`'s internal `_restartDepth + 1` bump on
      // the resumed call. See the proactive escalation comment above
      // for the symmetry rationale.
      return wrapStreamWithErrorHandler(
        createSummarizationStream(
          messagesContainer.current,
          opts,
          providerModel,
        ),
        messagesContainer,
        opts,
        providerModel,
        silent,
      );
    }
    if (!silent) {
      log.error("Non-context length error, re-throwing", {
        error: outerErrorMessage,
      });
    }

    // Re-throw if it's not a context length error
    throw error;
  }
}

export interface GenerateObjectOpts<T extends z.ZodType> {
  model: AIModel;
  schema: T;
  prompt: string;
  system?: string;
  maxTokens?: number;
  temperature?: number;
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  onTokenUsage?: (inputTokens: number, outputTokens: number) => void;
  /** Session id (`ses_…`) of the caller — stamped onto AI-span telemetry. */
  sessionId?: string;
}

const MAX_OBJECT_RATE_LIMIT_RETRIES = 8;

export async function generateObjectResponse<T extends z.ZodType>(
  opts: GenerateObjectOpts<T>,
): Promise<z.infer<T>> {
  const {
    model,
    schema,
    prompt,
    system,
    maxTokens,
    temperature,
    openAIReasoningEffort,
    authConfig,
    abortSignal,
    onTokenUsage,
    sessionId,
  } = opts;

  const providerModel = getProviderModel(model, authConfig);
  const normalizedOpenAIEffort = normalizeOpenAIReasoningEffort(
    model,
    openAIReasoningEffort,
  );

  let lastError: unknown;

  for (let attempt = 0; attempt <= MAX_OBJECT_RATE_LIMIT_RETRIES; attempt++) {
    try {
      const recordPayloads = shouldRecordAiPayloads();
      const { output, usage } = await generateText({
        model: providerModel,
        output: Output.object({
          schema,
        }),
        prompt,
        system,
        maxOutputTokens: maxTokens,
        temperature,
        providerOptions: normalizedOpenAIEffort
          ? {
              openai: {
                reasoningEffort: normalizedOpenAIEffort,
              },
            }
          : undefined,
        maxRetries: 0,
        abortSignal,
        experimental_telemetry: {
          isEnabled: true,
          recordInputs: recordPayloads,
          recordOutputs: recordPayloads,
          functionId: "apex.generate_object",
          ...(sessionId ? { metadata: { sessionId } } : {}),
        },
      });

      if (onTokenUsage && usage) {
        onTokenUsage(usage.inputTokens ?? 0, usage.outputTokens ?? 0);
      }

      if (_usageCallback && usage) {
        const inp = usage.inputTokens ?? 0;
        const out = usage.outputTokens ?? 0;
        const stepCtx = takeStepContext();
        if (inp > 0 || out > 0) _usageCallback(model, inp, out, stepCtx);
      }

      // zod v4: the AI SDK's `Output.object` no longer carries the schema's
      // inferred type through `output` (it widens to `unknown`), so restore it
      // from the schema generic for callers.
      return output as z.infer<T>;
    } catch (error) {
      lastError = error;

      if (checkIfContextLengthError(error)) {
        const msg = error instanceof Error ? error.message : String(error);
        throw new ContextLengthError(
          `Prompt exceeds model context window: ${msg}`,
        );
      }

      if (
        checkIfRateLimitError(error) &&
        attempt < MAX_OBJECT_RATE_LIMIT_RETRIES
      ) {
        const delayMs = Math.min(1000 * 2 ** attempt, 60_000);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        continue;
      }

      throw error;
    }
  }

  throw lastError;
}

class ContextLengthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContextLengthError";
  }
}

/**
 * Terminal: all recovery paths exhausted. The only context-length error
 * allowed to escape `streamResponse` — others are recoverable by design.
 */
export class ContextLengthExhaustedError extends Error {
  readonly restartDepth: number;
  constructor(message: string, restartDepth: number) {
    super(message);
    this.name = "ContextLengthExhaustedError";
    this.restartDepth = restartDepth;
  }
}

const MAX_RESTART_DEPTH = 3;

const MAX_TOOL_INPUT_CHARS = 8_000;
const MAX_SCHEMA_CHARS = 6_000;

const MINIMAL_RESTART_PROMPT =
  "Continue the previous task. Earlier context was discarded due to repeated context-length errors.";

export {
  applySequentialToolCallPolicy,
  createToolExecutionGate,
  SEQUENTIAL_TOOL_CALL_INSTRUCTION,
  StreamIdleTimeoutError,
  withIdleTimeout,
};

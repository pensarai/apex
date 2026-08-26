import { createLogger } from "../../logger/structured";
import { scopedLogger } from "../../util/lazyLogger";

// ---------------------------------------------------------------------------
// Stream diagnostics — opt-in observability for the agent stream: a stall
// watchdog (byte-silent streams), stream-gap recovery warnings, and the
// `response` tool lifecycle tracer. Purely observational; never touches tool
// state or stream iteration.
// ---------------------------------------------------------------------------

const STREAM_STALL_DEBUG =
  process.env.STREAM_STALL_DEBUG === "1" ||
  process.env.STREAM_STALL_DEBUG === "true";
const STREAM_STALL_TICK_MS = 15_000;
const STREAM_STALL_WARN_MS = 20_000;
const STREAM_GAP_RECOVERED_MS = 10_000;

const RESPONSE_DEBUG =
  process.env.RESPONSE_DEBUG === "1" || process.env.RESPONSE_DEBUG === "true";

const rlog = scopedLogger(() => createLogger("response-debug"));

/** Byte size of a streamed tool input, for the response-debug tracer. */
export function responseArgBytes(input: unknown): number {
  if (input == null) return 0;
  if (typeof input === "string") return input.length;
  try {
    return JSON.stringify(input).length;
  } catch {
    return -1;
  }
}

/** Structural chunk view the diagnostics read. */
export interface DiagnosticsChunk {
  type: string;
  id?: string;
  toolCallId?: string;
  toolName?: string;
  delta?: string;
  input?: unknown;
  args?: unknown;
  error?: unknown;
  invalid?: boolean;
  finishReason?: string;
}

export interface StreamDiagnosticsOptions {
  sessionId: string;
  subagentId?: string;
  /** Live in-flight tool view (owned by the lifecycle tracker). */
  inFlightTools: () => ReadonlyMap<string, string>;
  /** Whether the `response` tool has fired (owned by the agent). */
  responseToolFired: () => boolean;
  /** Tool name treated as the structured-response tool. */
  responseToolName: string;
  /** Stall watchdog + gap tracking; defaults to STREAM_STALL_DEBUG. */
  stallEnabled?: boolean;
  /** Response-tool lifecycle tracing; defaults to RESPONSE_DEBUG. */
  responseDebugEnabled?: boolean;
  /** Warn sink; defaults to the scoped response-debug logger. */
  warn?: (message: string) => void;
}

export class StreamDiagnostics {
  private readonly opts: StreamDiagnosticsOptions;
  private readonly stallEnabled: boolean;
  private readonly responseDebugEnabled: boolean;
  private readonly warn: (message: string) => void;
  private readonly responseArgChars = new Map<string, number>();
  private readonly responseSawTerminal = new Map<string, string>();

  private lastChunkAt = Date.now();
  private lastChunkType = "none";
  private stallStepIndex = -1;
  private stallTimer: ReturnType<typeof setInterval> | undefined;

  constructor(options: StreamDiagnosticsOptions) {
    this.opts = options;
    this.stallEnabled = options.stallEnabled ?? STREAM_STALL_DEBUG;
    this.responseDebugEnabled = options.responseDebugEnabled ?? RESPONSE_DEBUG;
    this.warn = options.warn ?? ((message: string) => rlog.warn(message));
  }

  /** Start the stall watchdog interval (no-op when disabled). */
  start(): void {
    if (!this.stallEnabled || this.stallTimer) return;
    const label = this.opts.sessionId;
    const sid = this.opts.subagentId;
    this.stallTimer = setInterval(() => {
      const gap = Date.now() - this.lastChunkAt;
      if (gap > STREAM_STALL_WARN_MS) {
        this.warn(
          `[stream-stall] no chunk for ${Math.round(gap / 1000)}s ` +
            `session=${label} subagent=${sid ?? "-"} step=${this.stallStepIndex} ` +
            `lastChunkType=${this.lastChunkType} ` +
            `inFlightTools=${[...this.opts.inFlightTools().values()].join(",")} ` +
            `responseToolFired=${this.opts.responseToolFired()}`,
        );
      }
    }, STREAM_STALL_TICK_MS);
  }

  /** Observe one stream chunk: gap tracking plus response-debug tracing. */
  observeChunk(chunk: DiagnosticsChunk): void {
    if (this.stallEnabled) {
      const now = Date.now();
      const gap = now - this.lastChunkAt;
      this.lastChunkAt = now;
      this.lastChunkType = chunk.type;
      if (chunk.type === "start-step") this.stallStepIndex++;
      if (gap > STREAM_GAP_RECOVERED_MS) {
        this.warn(
          `[stream-gap] recovered after ${Math.round(gap / 1000)}s ` +
            `session=${this.opts.sessionId} chunkType=${chunk.type}`,
        );
      }
    }
    if (this.responseDebugEnabled) {
      this.traceResponseTool(chunk);
    }
  }

  /** Response-debug: a deferred tool-error surfaced at finish-step. */
  logSurfacedToolError(info: {
    toolCallId: string;
    toolName: string;
    message: string;
    streamedArgChars: number;
    finishReason?: string;
    truncated: boolean;
  }): void {
    if (!this.responseDebugEnabled) return;
    if (info.toolName !== this.opts.responseToolName) return;
    this.warn(
      `[response-debug] tool-error SURFACED id=${info.toolCallId} ` +
        `streamedArgChars=${info.streamedArgChars} ` +
        `finishReason=${info.finishReason ?? "unknown"} ` +
        `outputTokenTruncated=${info.truncated} error=${info.message.slice(0, 300)}`,
    );
  }

  /** Response-debug: an in-flight call closed at finish-step. */
  logClosingInFlightTool(info: {
    toolCallId: string;
    toolName: string;
    finishReason?: string;
    truncated: boolean;
  }): void {
    if (!this.responseDebugEnabled) return;
    if (info.toolName !== this.opts.responseToolName) return;
    this.warn(
      `[response-debug] CLOSING response as "did not complete" id=${info.toolCallId} ` +
        `streamedArgChars=${this.responseArgChars.get(info.toolCallId) ?? 0} ` +
        `sawTerminalChunk=${this.responseSawTerminal.get(info.toolCallId) ?? "none"} ` +
        `finishReason=${info.finishReason ?? "unknown"} outputTokenTruncated=${info.truncated} ` +
        `responseToolFired=${this.opts.responseToolFired()}`,
    );
  }

  /** Stop the stall watchdog so it never leaks past stream end / throw. */
  stop(): void {
    if (this.stallTimer) clearInterval(this.stallTimer);
    this.stallTimer = undefined;
  }

  private traceResponseTool(chunk: DiagnosticsChunk): void {
    const idForChunk = chunk.toolCallId ?? chunk.id;
    const nameForChunk =
      chunk.toolName ??
      (idForChunk ? this.opts.inFlightTools().get(idForChunk) : undefined);
    if (nameForChunk !== this.opts.responseToolName || !idForChunk) {
      if (chunk.type === "finish-step") {
        // finish-step has no tool id; report every response call still in flight.
        const responseInFlight = [...this.opts.inFlightTools().entries()]
          .filter(([, n]) => n === this.opts.responseToolName)
          .map(([id]) => id)
          .join(",");
        if (responseInFlight) {
          this.warn(
            `[response-debug] finish-step finishReason=${chunk.finishReason} ` +
              `responseInFlight=${responseInFlight} ` +
              `responseToolFired=${this.opts.responseToolFired()}`,
          );
        }
      }
      return;
    }
    switch (chunk.type) {
      case "tool-input-start":
        this.responseArgChars.set(idForChunk, 0);
        this.warn(
          `[response-debug] tool-input-start id=${idForChunk} session=${this.opts.sessionId}`,
        );
        break;
      case "tool-input-delta":
        this.responseArgChars.set(
          idForChunk,
          (this.responseArgChars.get(idForChunk) ?? 0) +
            (chunk.delta?.length ?? 0),
        );
        break;
      case "tool-input-end":
        this.warn(
          `[response-debug] tool-input-end id=${idForChunk} argChars=${this.responseArgChars.get(idForChunk) ?? 0}`,
        );
        break;
      case "tool-call": {
        this.responseSawTerminal.set(idForChunk, "tool-call");
        const inputBytes = responseArgBytes(chunk.input ?? chunk.args);
        this.warn(
          `[response-debug] tool-call id=${idForChunk} streamedArgChars=${this.responseArgChars.get(idForChunk) ?? 0} parsedInputBytes=${inputBytes} invalid=${chunk.invalid === true}`,
        );
        break;
      }
      case "tool-error": {
        this.responseSawTerminal.set(idForChunk, "tool-error");
        const errMsg =
          chunk.error instanceof Error
            ? chunk.error.message
            : typeof chunk.error === "string"
              ? chunk.error
              : JSON.stringify(chunk.error)?.slice(0, 300);
        this.warn(
          `[response-debug] tool-error id=${idForChunk} streamedArgChars=${this.responseArgChars.get(idForChunk) ?? 0} stillInFlight=${this.opts.inFlightTools().has(idForChunk)} error=${errMsg}`,
        );
        break;
      }
      case "tool-result":
        this.responseSawTerminal.set(idForChunk, "tool-result");
        this.warn(
          `[response-debug] tool-result id=${idForChunk} streamedArgChars=${this.responseArgChars.get(idForChunk) ?? 0}`,
        );
        break;
    }
  }
}

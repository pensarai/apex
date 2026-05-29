/**
 * Tiered context compaction. Layer 1 truncates large tool results;
 * Layer 2 snips old tool results to 1-line summaries; Layer 3
 * (`summarizeConversation` in utils.ts) is the fallback.
 * {@link fitMessagesToContext} composes Layer 1+2 against an explicit
 * token budget so callers can compact proactively, not only on error.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ModelMessage, ToolSet } from "ai";

/**
 * Truncate `text` so the returned string fits in **at most** `max` chars,
 * and append a marker noting how many were dropped. `label` selects the
 * marker form: omit for the verbose `"…[truncated N chars]"` (used wherever
 * the recipient might benefit from the byte count), pass a label for
 * `"…[<label> truncated]"` when the count would be misleading or noisy.
 *
 * `max` is a strict upper bound — the marker length is reserved INSIDE
 * `max`, not appended outside it. Callers (`MAX_TOOL_INPUT_CHARS`,
 * `MAX_SCHEMA_CHARS`, `MAX_PER_MESSAGE_CHARS`, `SYSTEM_PROMPT_SNIPPET_CHARS`)
 * treat the cap as a hard ceiling on auxiliary-LLM input size; soft caps
 * would silently inflate budgets by ~30 chars per call.
 *
 * Degenerate `max < marker.length` returns just the marker (still useful
 * signal vs. a meaningless ≤30-char head slice).
 */
export function truncateWithMarker(
  text: string,
  max: number,
  label?: string,
): string {
  if (text.length <= max) return text;
  if (label) {
    const marker = `…[${label} truncated]`;
    const sliceLen = Math.max(0, max - marker.length);
    return `${text.slice(0, sliceLen)}${marker}`;
  }
  // Marker width depends on the dropped-char count — but the count itself
  // depends on the slice length. Reserve the worst-case width (digits of
  // `text.length`, an upper bound on `dropped`) so the final output is
  // always ≤ `max` regardless of how the count formats.
  const widestMarker = `…[truncated ${text.length} chars]`;
  const sliceLen = Math.max(0, max - widestMarker.length);
  const dropped = text.length - sliceLen;
  return `${text.slice(0, sliceLen)}…[truncated ${dropped} chars]`;
}

// Layer 1: Tool Result Truncation

// 10K chars (~2.5K tokens). Larger thresholds let many mid-size results
// collectively exceed the budget without any single one tripping it.
const DEFAULT_MAX_RESULT_CHARS = 10_000;

/**
 * Matches the trailing metadata block emitted by `applyToolResultBudget`.
 * Lets cascading-threshold re-truncation recover the ORIGINAL length and
 * disk path so the new metadata reports the correct dropped-char count
 * instead of the (preview→smaller-preview) delta — which would hide the
 * true magnitude of data loss from the model.
 */
const TOOL_RESULT_TRUNCATION_TAIL =
  /\n\n\[\.\.\. truncated (\d+) chars — full output saved to (.+?)\]$/;

/** Small + critical for agent state — never snip. */
const TASK_TOOL_NAMES = new Set(["create_task", "update_task", "list_tasks"]);

/**
 * Replace large tool results in message history with truncated previews.
 * Full results are persisted to disk at `{sessionPath}/tool-results/`.
 *
 * Returns a new messages array (does not mutate the input).
 *
 * `persistedIds`, when passed, deduplicates writes across cascading calls
 * (e.g. `fitMessagesToContext` invokes this with progressively tighter
 * thresholds — the original full output only needs to land on disk once).
 */
export function applyToolResultBudget(
  messages: ModelMessage[],
  opts: {
    sessionPath: string;
    maxResultChars?: number;
    persistedIds?: Set<string>;
  },
): ModelMessage[] {
  const maxChars = opts.maxResultChars ?? DEFAULT_MAX_RESULT_CHARS;
  const resultsDir = join(opts.sessionPath, "tool-results");
  const persistedIds = opts.persistedIds;
  let dirCreated = false;
  let anyModified = false;

  const result = messages.map((msg) => {
    if (!Array.isArray(msg.content)) return msg;

    let msgModified = false;
    const newContent = (msg.content as unknown[]).map((part) => {
      const p = part as Record<string, unknown>;
      if (p.type !== "tool-result") return part;

      const toolName = String(p.toolName ?? "tool");
      if (TASK_TOOL_NAMES.has(toolName)) return part;

      const text = stringifyToolOutput(p.output ?? p.result);

      // Detect re-entry on cascading thresholds. If this entry was
      // truncated by an earlier pass (10K → 5K → 2K → 500), `text` is
      // already a `<preview>\n\n[... truncated N chars — full output
      // saved to PATH]` composite. Strip the tail so the budget check
      // and subsequent slice operate on the preview body, and recover
      // the original length / disk path so the new metadata stays
      // honest instead of reporting `previewLen - newPreviewLen` (which
      // hides the real magnitude of data loss).
      const tailMatch = text.match(TOOL_RESULT_TRUNCATION_TAIL);
      const previewBody = tailMatch ? text.slice(0, tailMatch.index) : text;
      const previousDropped = tailMatch ? Number(tailMatch[1]) : 0;
      const originalLength = previewBody.length + previousDropped;

      // Brand-new entries that already fit need no compaction. Re-entries
      // (`tailMatch !== null`) skip this guard so the cascading thresholds
      // {10K, 5K, 2K, 500} can each progressively tighten an already-
      // truncated preview — the monotone-reduction guard below ensures
      // we never replace with something larger than what's already there.
      if (!tailMatch && previewBody.length <= maxChars) return part;

      const toolCallId = String(p.toolCallId ?? "unknown");
      const filePath = tailMatch
        ? tailMatch[2]!
        : join(resultsDir, `${toolCallId}.txt`);

      // Preview must scale with `maxChars` so cascading thresholds
      // {10K, 5K, 2K, 500} achieve progressively tighter compaction on
      // already-truncated entries (a fixed 2000-char preview would
      // make the 5K and 2K passes no-ops on entries the 10K pass had
      // already shrunk to ~2080 chars). 1/5 of the threshold gives:
      // 10K → 2000-char preview, 5K → 1000, 2K → 400, 500 → 100.
      // Floor of 100 keeps the smallest preview useful; the
      // monotone-reduction guard below catches any pathological case.
      const previewSize = Math.max(100, Math.floor(maxChars / 5));
      const preview = previewBody.slice(0, previewSize);
      // `preview.length`, not `previewSize`: when re-entering on a
      // small `previewBody` (already heavily truncated), the slice
      // is shorter than `previewSize`, so the dropped-char count must
      // reference what the preview ACTUALLY contains, otherwise the
      // metadata understates the data loss by `previewSize -
      // previewBody.length` chars.
      const newValue = `${preview}\n\n[... truncated ${originalLength - preview.length} chars — full output saved to ${filePath}]`;

      // Monotone-reduction guard: near the threshold boundary
      // (e.g. text.length=2050 against maxChars=2000), preview + ~80
      // chars of metadata can be LARGER than the original. Returning a
      // bigger value would inflate `estimatedInputTokens` and break
      // invariant I2. Bail out BEFORE persistence — we don't want to
      // write the file for an entry we won't actually compact, and the
      // next tighter cascading threshold (or Layer 2 / Layer 3) will get
      // another shot at it.
      if (newValue.length >= text.length) return part;

      if (!persistedIds || !persistedIds.has(toolCallId)) {
        // If this entry already carried a truncation tail, the full
        // output was persisted by an earlier pass — `text` is just the
        // preview, so writing it back would clobber the disk file with
        // a partial. The earlier path stays the source of truth.
        if (!tailMatch) {
          if (!dirCreated) {
            mkdirSync(resultsDir, { recursive: true });
            dirCreated = true;
          }
          try {
            writeFileSync(filePath, text, "utf-8");
          } catch {
            // Non-critical: full output may be lost.
          }
        }
        persistedIds?.add(toolCallId);
      }

      msgModified = true;
      return {
        ...p,
        output: {
          type: "text" as const,
          value: newValue,
        },
      };
    });

    if (msgModified) anyModified = true;
    return msgModified
      ? ({ ...msg, content: newContent } as ModelMessage)
      : msg;
  });

  // Reference equality lets callers detect "no change".
  return anyModified ? result : messages;
}

// Layer 2: Step Snipping

// Larger windows can blow the budget on the "recent" slice alone; 6 leaves
// enough recent context to make progress while letting Layer 2 actually compact.
const DEFAULT_KEEP_RECENT_STEPS = 6;

/**
 * For tool results older than `keepRecentSteps`, replace with 1-line summaries.
 * Returns a new array (does not mutate input).
 */
function snipOldSteps(
  messages: ModelMessage[],
  opts?: { keepRecentSteps?: number },
): ModelMessage[] {
  const keepRecent = opts?.keepRecentSteps ?? DEFAULT_KEEP_RECENT_STEPS;

  let stepCount = 0;
  let cutoffIdx = 0;
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]!.role === "assistant") {
      stepCount++;
      if (stepCount === keepRecent) {
        cutoffIdx = i;
        break;
      }
    }
  }

  if (cutoffIdx === 0) return messages;

  let anyModified = false;
  const result = messages.map((msg, idx) => {
    if (idx >= cutoffIdx) return msg;
    if (!Array.isArray(msg.content)) return msg;

    let msgModified = false;
    const newContent = (msg.content as unknown[]).map((part) => {
      const p = part as Record<string, unknown>;
      if (p.type !== "tool-result") return part;

      const toolName = String(p.toolName ?? "tool");
      if (TASK_TOOL_NAMES.has(toolName)) return part;

      const text = stringifyToolOutput(p.output ?? p.result);

      // Already a 1-line summary from a previous pass.
      if (text.startsWith(`[${toolName}] →`) && !text.includes("\n"))
        return part;

      msgModified = true;
      return {
        ...p,
        output: {
          type: "text" as const,
          value: generateToolResultSummary(toolName, text),
        },
      };
    });

    if (msgModified) anyModified = true;
    return msgModified
      ? ({ ...msg, content: newContent } as ModelMessage)
      : msg;
  });

  return anyModified ? result : messages;
}

/**
 * Pull the latest task summary from a `list_tasks` tool result so it can
 * survive Layer 3 summarization.
 */
export function extractTaskSummaryFromMessages(
  messages: ModelMessage[],
): string | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i]!;
    if (!Array.isArray(msg.content)) continue;

    for (const part of msg.content as unknown[]) {
      const p = part as Record<string, unknown>;
      if (p.type !== "tool-result" || p.toolName !== "list_tasks") continue;

      const text = stringifyToolOutput(p.output ?? p.result);
      if (!text.includes('"summary"')) continue;

      try {
        const parsed = JSON.parse(text) as {
          summary?: {
            total: number;
            completed: number;
            failed: number;
            pending: number;
            in_progress: number;
          };
        };
        if (parsed.summary) {
          const s = parsed.summary;
          return `Tasks: ${s.total} total (${s.completed} completed, ${s.failed} failed, ${s.pending} pending, ${s.in_progress} in progress)`;
        }
      } catch {
        // Not valid JSON
      }
    }
  }

  return null;
}

// Token estimation + budget-driven fitting

/** Conservative ~4 chars/token; `safetyMarginTokens` absorbs drift. */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Tool schemas are the dominant per-request overhead for tool-heavy agents
 * (15–25K tokens in production traces), not a small constant. Estimating
 * directly from the actual `ToolSet` keeps the budget honest.
 *
 * Memoized by `ToolSet` reference: schemas are immutable once registered,
 * and this runs on every `streamResponse` call (proactive fit + reactive
 * recovery), so re-stringifying every schema each time is pure waste.
 */
const toolsOverheadCache = new WeakMap<ToolSet, number>();
export function estimateToolsOverheadTokens(tools?: ToolSet): number {
  if (!tools) return 0;
  const cached = toolsOverheadCache.get(tools);
  if (cached !== undefined) return cached;
  let chars = 0;
  for (const [name, tool] of Object.entries(tools)) {
    chars += name.length;
    const t = tool as Record<string, unknown>;
    if (typeof t.description === "string") chars += t.description.length;
    if (t.inputSchema) {
      try {
        chars += JSON.stringify(t.inputSchema).length;
      } catch {
        // Cyclic / non-serialisable — never zero.
        chars += 500;
      }
    }
  }
  const tokens = Math.ceil(chars / 4);
  toolsOverheadCache.set(tools, tokens);
  return tokens;
}

/** Walks parts directly to avoid `JSON.stringify` on a large history. */
export function estimateMessageTokens(messages: ModelMessage[]): number {
  let chars = 0;
  for (const msg of messages) {
    chars += 8;
    if (typeof msg.content === "string") {
      chars += msg.content.length;
      continue;
    }
    if (!Array.isArray(msg.content)) continue;
    for (const part of msg.content as Array<Record<string, unknown>>) {
      const t = part.type;
      if (t === "text" && typeof part.text === "string") {
        chars += part.text.length;
      } else if (t === "tool-call") {
        const input = part.input;
        chars +=
          typeof input === "string"
            ? input.length
            : JSON.stringify(input ?? "").length;
        if (typeof part.toolName === "string") chars += part.toolName.length;
      } else if (t === "tool-result") {
        chars += stringifyToolOutput(part.output ?? part.result).length;
        if (typeof part.toolName === "string") chars += part.toolName.length;
      } else {
        chars += JSON.stringify(part).length;
      }
    }
  }
  return Math.ceil(chars / 4);
}

export interface FitContextResult {
  messages: ModelMessage[];
  /** Token estimate of `messages` (excludes system + overhead). */
  estimatedInputTokens: number;
  /** Reference inequality vs. input. */
  modified: boolean;
  /** `false` ⇒ caller must escalate to Layer 3 summarization. */
  fitsBudget: boolean;
}

export interface FitContextOpts {
  contextWindow: number;
  /** Tokens reserved for the model's response (`max_tokens`). */
  maxOutputTokens: number;
  /** Counted toward input; never compacted here. */
  system?: string;
  /** Used to size tool-schema overhead. Pass `tools` OR `overheadTokens`. */
  tools?: ToolSet;
  /** Explicit override; otherwise derived from `tools` + 1K fmt allowance. */
  overheadTokens?: number;
  /** Absorbs chars/4 drift; default 10_000. */
  safetyMarginTokens?: number;
  /** Required to enable Layer 1 (results persisted to disk). */
  sessionPath?: string;
}

/**
 * Single entry point for proactive AND reactive compaction. Iteratively
 * tightens thresholds — Layer 1 ∈ {10K, 5K, 2K, 500} chars, then Layer 2
 * ∈ {6, 3, 1} steps — and short-circuits the moment the estimate fits.
 * Returns `fitsBudget: false` when the caller must escalate to Layer 3.
 */
export function fitMessagesToContext(
  messages: ModelMessage[],
  opts: FitContextOpts,
): FitContextResult {
  const overhead =
    opts.overheadTokens ?? estimateToolsOverheadTokens(opts.tools) + 1_000;
  const safety = opts.safetyMarginTokens ?? 10_000;
  const systemTokens = opts.system ? estimateTokens(opts.system) : 0;
  const messagesBudget =
    opts.contextWindow -
    opts.maxOutputTokens -
    overhead -
    safety -
    systemTokens;

  // Even an empty message list exceeds the budget — escalate.
  if (messagesBudget <= 0) {
    return {
      messages,
      estimatedInputTokens: estimateMessageTokens(messages),
      modified: false,
      fitsBudget: false,
    };
  }

  let current = messages;
  let estimate = estimateMessageTokens(current);
  if (estimate <= messagesBudget) {
    return {
      messages,
      estimatedInputTokens: estimate,
      modified: false,
      fitsBudget: true,
    };
  }

  // Shared across cascading Layer 1 thresholds so the same full tool result
  // is persisted to disk at most once, not 4× at progressively smaller
  // preview sizes.
  const persistedIds = opts.sessionPath ? new Set<string>() : undefined;

  const fits = (): FitContextResult => ({
    messages: current,
    estimatedInputTokens: estimate,
    modified: current !== messages,
    fitsBudget: true,
  });

  // Layer 1 requires sessionPath (results are persisted to disk).
  if (opts.sessionPath) {
    for (const maxResultChars of [10_000, 5_000, 2_000, 500]) {
      const next = applyToolResultBudget(current, {
        sessionPath: opts.sessionPath,
        maxResultChars,
        persistedIds,
      });
      // No-op layer ⇒ re-estimation would yield the same number.
      if (next === current) continue;
      current = next;
      estimate = estimateMessageTokens(current);
      if (estimate <= messagesBudget) return fits();
    }
  }

  for (const keepRecentSteps of [6, 3, 1]) {
    const next = snipOldSteps(current, { keepRecentSteps });
    if (next === current) continue;
    current = next;
    estimate = estimateMessageTokens(current);
    if (estimate <= messagesBudget) return fits();
  }

  return {
    messages: current,
    estimatedInputTokens: estimate,
    modified: current !== messages,
    fitsBudget: false,
  };
}

function stringifyToolOutput(output: unknown): string {
  if (output == null) return "";
  if (typeof output === "string") return output;
  if (
    typeof output === "object" &&
    "value" in (output as Record<string, unknown>)
  ) {
    const val = (output as { value: unknown }).value;
    return typeof val === "string" ? val : JSON.stringify(val);
  }
  return JSON.stringify(output);
}

function generateToolResultSummary(toolName: string, text: string): string {
  const len = text.length;
  const lines = text.split("\n").length;

  if (toolName === "http_request") {
    const statusMatch = text.match(/(\d{3})\s/);
    const status = statusMatch ? statusMatch[1] : "???";
    return `[${toolName}] → ${status} (${len} chars, ${lines} lines)`;
  }

  if (toolName === "execute_command") {
    const exitMatch = text.match(/exit.?code[:\s]*(\d+)/i);
    const exit = exitMatch ? exitMatch[1] : "?";
    return `[${toolName}] → exit ${exit} (${len} chars, ${lines} lines)`;
  }

  return `[${toolName}] → ${len} chars, ${lines} lines`;
}

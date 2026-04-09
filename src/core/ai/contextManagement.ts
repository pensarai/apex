/**
 * Multi-Layer Context Management
 *
 * Tiered compaction strategy inspired by Claude Code's 5-layer system,
 * adapted for Apex's architecture. Applied in order when context overflows:
 *
 * Layer 1: Tool result truncation — large results replaced with previews
 * Layer 2: Step snipping — old tool results condensed to 1-line summaries
 *
 * Full summarization (existing in utils.ts) remains as Layer 3 fallback.
 */

import type { ModelMessage } from "ai";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// ---------------------------------------------------------------------------
// Layer 1: Tool Result Truncation
// ---------------------------------------------------------------------------

const DEFAULT_MAX_RESULT_CHARS = 50_000;

/** Task tool results are small and critical for agent state — never snip them. */
const TASK_TOOL_NAMES = new Set(["create_task", "update_task", "list_tasks"]);

/**
 * Replace large tool results in message history with truncated previews.
 * Full results are persisted to disk at `{sessionPath}/tool-results/`.
 *
 * Returns a new messages array (does not mutate the input).
 */
export function applyToolResultBudget(
  messages: ModelMessage[],
  opts: { sessionPath: string; maxResultChars?: number },
): ModelMessage[] {
  const maxChars = opts.maxResultChars ?? DEFAULT_MAX_RESULT_CHARS;
  const resultsDir = join(opts.sessionPath, "tool-results");
  let dirCreated = false;
  let anyModified = false;

  const result = messages.map((msg) => {
    if (!Array.isArray(msg.content)) return msg;

    let msgModified = false;
    const newContent = (msg.content as unknown[]).map((part) => {
      const p = part as Record<string, unknown>;
      if (p.type !== "tool-result") return part;

      const text = stringifyToolOutput(p.output ?? p.result);
      if (text.length <= maxChars) return part;

      // Persist full result to disk
      if (!dirCreated) {
        mkdirSync(resultsDir, { recursive: true });
        dirCreated = true;
      }

      const toolCallId = String(p.toolCallId ?? "unknown");
      const filePath = join(resultsDir, `${toolCallId}.txt`);
      try {
        writeFileSync(filePath, text, "utf-8");
      } catch {
        // Non-critical — worst case, full output is lost
      }

      msgModified = true;
      const preview = text.slice(0, 2000);
      return {
        ...p,
        output: {
          type: "text" as const,
          value: `${preview}\n\n[... truncated ${text.length - 2000} chars — full output saved to ${filePath}]`,
        },
      };
    });

    if (msgModified) anyModified = true;
    return msgModified
      ? ({ ...msg, content: newContent } as ModelMessage)
      : msg;
  });

  // Return original array when nothing was truncated so callers
  // can use reference equality to detect changes.
  return anyModified ? result : messages;
}

// ---------------------------------------------------------------------------
// Layer 2: Step Snipping
// ---------------------------------------------------------------------------

const DEFAULT_KEEP_RECENT_STEPS = 15;

/**
 * For tool results older than `keepRecentSteps`, replace with 1-line summaries.
 * Keeps full content for recent steps to preserve context for active work.
 *
 * Returns a new messages array (does not mutate the input).
 */
export function snipOldSteps(
  messages: ModelMessage[],
  opts?: { keepRecentSteps?: number },
): ModelMessage[] {
  const keepRecent = opts?.keepRecentSteps ?? DEFAULT_KEEP_RECENT_STEPS;

  // Find the index where "recent" starts by counting assistant messages from the end
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

  // Nothing to snip — all messages are within the recent window
  if (cutoffIdx === 0) return messages;

  return messages.map((msg, idx) => {
    // Keep recent messages intact
    if (idx >= cutoffIdx) return msg;
    if (!Array.isArray(msg.content)) return msg;

    let modified = false;
    const newContent = (msg.content as unknown[]).map((part) => {
      const p = part as Record<string, unknown>;
      if (p.type !== "tool-result") return part;

      const toolName = String(p.toolName ?? "tool");

      // Preserve task tool results — they're small and the agent
      // needs them to track task state after context compaction.
      if (TASK_TOOL_NAMES.has(toolName)) return part;

      const text = stringifyToolOutput(p.output ?? p.result);
      modified = true;
      return {
        ...p,
        output: {
          type: "text" as const,
          value: generateToolResultSummary(toolName, text),
        },
      };
    });

    return modified ? ({ ...msg, content: newContent } as ModelMessage) : msg;
  });
}

// ---------------------------------------------------------------------------
// Task state extraction (for preserving through summarization)
// ---------------------------------------------------------------------------

/**
 * Extract a task summary from messages for inclusion in context summaries.
 * Looks for recent list_tasks tool results to find the latest task state.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

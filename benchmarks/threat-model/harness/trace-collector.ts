/**
 * Threat Model Benchmark — Trace Collector
 *
 * Wraps AgentEventBus to capture tool calls, step counts,
 * and token usage (including cache metrics) for behavioral analysis.
 */

import { AgentEventBus } from "../../../src/core/eventBus";
import type { BehavioralMetrics, TokenMetrics, ToolCallRecord } from "./types";

const SOURCE_EXTS =
  /\.(ts|tsx|py|go|rs|php|java|rb|js|jsx|vue|svelte|c|cpp|h|cs|swift|kt)$/;

// Pricing per million tokens (as of 2026-04)
const PRICING: Record<string, { input: number; output: number; cacheRead: number; cacheWrite: number }> = {
  "claude-opus-4-6":   { input: 15, output: 75, cacheRead: 1.5, cacheWrite: 18.75 },
  "claude-sonnet-4-6": { input: 3,  output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  "claude-sonnet-4-5": { input: 3,  output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  "claude-haiku-4-5":  { input: 0.8, output: 4, cacheRead: 0.08, cacheWrite: 1 },
};

function estimateCost(tokens: Omit<TokenMetrics, "totalTokens" | "estimatedCostUsd">, model: string): number {
  const pricing = PRICING[model] ?? PRICING["claude-sonnet-4-5"];
  const perM = 1_000_000;

  // Input tokens that weren't cached
  const noCacheInput = Math.max(0, tokens.inputTokens - tokens.cacheReadTokens - tokens.cacheWriteTokens);

  return (
    (noCacheInput / perM) * pricing.input +
    (tokens.cacheReadTokens / perM) * pricing.cacheRead +
    (tokens.cacheWriteTokens / perM) * pricing.cacheWrite +
    (tokens.outputTokens / perM) * pricing.output
  );
}

export class TraceCollector {
  readonly eventBus = new AgentEventBus();
  private toolCalls: ToolCallRecord[] = [];
  private steps = 0;
  private startTime = Date.now();
  private model = "claude-sonnet-4-5";

  // Token accumulators
  private inputTokens = 0;
  private outputTokens = 0;
  private cacheReadTokens = 0;
  private cacheWriteTokens = 0;

  constructor(model?: string) {
    if (model) this.model = model;

    this.eventBus.on("tool-call-complete", (e) => {
      const args =
        typeof e.args === "object" && e.args !== null
          ? (e.args as Record<string, unknown>)
          : {};
      this.toolCalls.push({
        name: e.toolName,
        args,
        timestamp: Date.now(),
        subagentId: e.subagentId,
      });
    });

    this.eventBus.on("step-finish", () => {
      this.steps++;
    });

    // Capture token usage from trace records
    this.eventBus.on("trace-record", (e) => {
      const record = e.record as Record<string, unknown>;
      if (record.type === "step") {
        const usage = record.usage as Record<string, number> | undefined;
        if (usage) {
          this.inputTokens += usage.inputTokens ?? 0;
          this.outputTokens += usage.outputTokens ?? 0;
          this.cacheReadTokens += usage.cacheReadTokens ?? 0;
          this.cacheWriteTokens += usage.cacheWriteTokens ?? 0;
        }
      }
    });
  }

  getTokenSnapshot(): TokenMetrics {
    const total = this.inputTokens + this.outputTokens;
    return {
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      cacheReadTokens: this.cacheReadTokens,
      cacheWriteTokens: this.cacheWriteTokens,
      totalTokens: total,
      estimatedCostUsd: estimateCost(
        {
          inputTokens: this.inputTokens,
          outputTokens: this.outputTokens,
          cacheReadTokens: this.cacheReadTokens,
          cacheWriteTokens: this.cacheWriteTokens,
        },
        this.model,
      ),
    };
  }

  computeMetrics(): BehavioralMetrics {
    const reads = this.toolCalls.filter((t) => t.name === "read_file");
    const filePaths = reads
      .map((r) => (r.args.file_path ?? r.args.path) as string | undefined)
      .filter(Boolean) as string[];

    const uniqueFiles = new Set(filePaths);
    const uniqueSourceFiles = new Set(
      filePaths.filter((p) => SOURCE_EXTS.test(p)),
    );

    return {
      totalSteps: this.steps,
      wallClockMs: Date.now() - this.startTime,
      filesRead: uniqueFiles.size,
      sourceFilesRead: uniqueSourceFiles.size,
      grepCalls: this.toolCalls.filter((t) => t.name === "grep").length,
      shellCommands: this.toolCalls.filter((t) => t.name === "execute_command")
        .length,
      completionSuccess: false, // Set by runner after checking output file
      tokens: this.getTokenSnapshot(),
    };
  }

  export(): ToolCallRecord[] {
    return [...this.toolCalls];
  }
}

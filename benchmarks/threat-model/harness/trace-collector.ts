/**
 * Threat Model Benchmark — Trace Collector
 *
 * Wraps AgentEventBus to capture tool calls and step counts
 * for behavioral metric computation.
 */

import { AgentEventBus } from "../../../src/core/eventBus";
import type { BehavioralMetrics, ToolCallRecord } from "./types";

const SOURCE_EXTS =
  /\.(ts|tsx|py|go|rs|php|java|rb|js|jsx|vue|svelte|c|cpp|h|cs|swift|kt)$/;

export class TraceCollector {
  readonly eventBus = new AgentEventBus();
  private toolCalls: ToolCallRecord[] = [];
  private steps = 0;
  private startTime = Date.now();

  constructor() {
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
    };
  }

  export(): ToolCallRecord[] {
    return [...this.toolCalls];
  }
}

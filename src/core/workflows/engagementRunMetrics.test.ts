import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readExecutionMetrics } from "../session/execution-metrics";
import { EngagementRunMetrics } from "./engagementRunMetrics";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe("EngagementRunMetrics", () => {
  it("persists role/model usage, code cells, and explicit cost provenance", () => {
    const directory = mkdtempSync(join(tmpdir(), "apex-engagement-metrics-"));
    directories.push(directory);
    const metrics = new EngagementRunMetrics(directory);
    metrics.record("planner", "planner-model", {
      usage: {
        inputTokens: 100,
        outputTokens: 20,
        inputTokenDetails: { cacheReadTokens: 40, cacheWriteTokens: 5 },
      },
      providerMetadata: { openrouter: { cost: 0.012 } },
    } as never);
    metrics.record("worker", "worker-model", {
      usage: { inputTokens: 50, outputTokens: 10 },
    } as never);
    metrics.recordCode("worker", "worker-model", {
      cellId: "cell-1",
      status: "completed",
      output: "ok",
      metrics: {
        nestedCalls: 3,
        uniqueCalls: 3,
        repeatedCalls: 0,
        maxConcurrency: 2,
        durationMs: 120,
      },
    });
    metrics.finish("completed");

    const artifact = JSON.parse(
      readFileSync(
        join(directory, "coordination", "engagement-run-metrics.json"),
        "utf8",
      ),
    );
    expect(artifact).toMatchObject({
      status: "completed",
      totals: { inputTokens: 150, outputTokens: 30, cacheReadTokens: 40 },
      code: { cells: 1, nestedCalls: 3, maxConcurrency: 2 },
      cost: {
        status: "partial",
        amount: 0.012,
        missing: [{ role: "worker", model: "worker-model" }],
      },
    });
    expect(readExecutionMetrics(directory)?.tokenUsage).toMatchObject({
      inputTokens: 150,
      outputTokens: 30,
      totalTokens: 180,
    });
  });

  it("does not represent unavailable provider cost as zero", () => {
    const directory = mkdtempSync(join(tmpdir(), "apex-engagement-metrics-"));
    directories.push(directory);
    const metrics = new EngagementRunMetrics(directory);
    metrics.finish("failed");
    const artifact = JSON.parse(
      readFileSync(
        join(directory, "coordination", "engagement-run-metrics.json"),
        "utf8",
      ),
    );
    expect(artifact.cost).toEqual({ status: "unavailable" });
  });

  it("keeps terminal status when a late metric callback arrives", () => {
    const directory = mkdtempSync(join(tmpdir(), "apex-engagement-metrics-"));
    directories.push(directory);
    const metrics = new EngagementRunMetrics(directory);
    metrics.finish("completed");
    const completedAt = JSON.parse(
      readFileSync(
        join(directory, "coordination", "engagement-run-metrics.json"),
        "utf8",
      ),
    ).completedAt;

    metrics.record("lead", "lead-model", {
      usage: { inputTokens: 10, outputTokens: 2 },
    } as never);

    const artifact = JSON.parse(
      readFileSync(
        join(directory, "coordination", "engagement-run-metrics.json"),
        "utf8",
      ),
    );
    expect(artifact).toMatchObject({
      status: "completed",
      completedAt,
      totals: { inputTokens: 10, outputTokens: 2 },
    });
  });

  it("reports complete cost only when every used role and model reports it", () => {
    const directory = mkdtempSync(join(tmpdir(), "apex-engagement-metrics-"));
    directories.push(directory);
    const metrics = new EngagementRunMetrics(directory);
    metrics.record("worker", "worker-model", {
      usage: { inputTokens: 10, outputTokens: 2 },
      providerMetadata: { openrouter: { cost: 0.25 } },
    } as never);
    metrics.finish("completed");

    const artifact = JSON.parse(
      readFileSync(
        join(directory, "coordination", "engagement-run-metrics.json"),
        "utf8",
      ),
    );
    expect(artifact.cost).toEqual({ status: "reported", amount: 0.25 });
  });
});

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  readExecutionMetrics,
  writeExecutionMetrics,
} from "./execution-metrics";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "exec-metrics-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function rootPath(): string {
  return tmpDir;
}

function metricsPath(): string {
  return join(tmpDir, "execution-metrics.json");
}

function writeRaw(value: unknown): void {
  writeFileSync(metricsPath(), JSON.stringify(value, null, 2), "utf-8");
}

function readRaw(): Record<string, unknown> {
  return JSON.parse(readFileSync(metricsPath(), "utf-8"));
}

// ---------------------------------------------------------------------------
// writeExecutionMetrics / readExecutionMetrics — full shape
// ---------------------------------------------------------------------------

describe("execution-metrics round-trip", () => {
  it("persists and hydrates the complete usage shape", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: {
        inputTokens: 123_000,
        outputTokens: 18_000,
        cacheReadTokens: 90_000,
        cacheWriteTokens: 4_000,
        totalTokens: 141_000,
      },
      contextUsage: {
        usedTokens: 84_000,
        contextLimit: 200_000,
        modelId: "claude-sonnet-4-5",
      },
    });

    const metrics = readExecutionMetrics(rootPath());
    expect(metrics?.tokenUsage).toEqual({
      inputTokens: 123_000,
      outputTokens: 18_000,
      cacheReadTokens: 90_000,
      cacheWriteTokens: 4_000,
      totalTokens: 141_000,
    });
    expect(metrics?.contextUsage).toEqual({
      usedTokens: 84_000,
      contextLimit: 200_000,
      modelId: "claude-sonnet-4-5",
    });
  });

  it("writes the documented file shape (totalTokens present, cache inside input)", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: {
        inputTokens: 100,
        outputTokens: 20,
        cacheReadTokens: 90,
        cacheWriteTokens: 5,
      },
      contextUsage: {
        usedTokens: 10,
        contextLimit: 200,
        modelId: "m",
      },
    });

    const raw = readRaw();
    expect(raw.tokenUsage).toEqual({
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 90,
      cacheWriteTokens: 5,
      totalTokens: 120,
    });
    expect(raw.contextUsage).toEqual({
      usedTokens: 10,
      contextLimit: 200,
      modelId: "m",
    });
  });
});

// ---------------------------------------------------------------------------
// Legacy compatibility
// ---------------------------------------------------------------------------

describe("execution-metrics legacy compatibility", () => {
  it("hydrates legacy files lacking cache and context fields", () => {
    writeRaw({
      tokenUsage: { inputTokens: 7, outputTokens: 3, totalTokens: 10 },
      updatedAt: "2026-01-01T00:00:00.000Z",
    });

    const metrics = readExecutionMetrics(rootPath());
    expect(metrics?.tokenUsage).toEqual({
      inputTokens: 7,
      outputTokens: 3,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      totalTokens: 10,
    });
    expect(metrics?.contextUsage).toBeUndefined();
    expect(metrics?.updatedAt).toBe("2026-01-01T00:00:00.000Z");
  });

  it("legacy callers writing without cache fields keep existing cache totals", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: {
        inputTokens: 100,
        outputTokens: 20,
        cacheReadTokens: 90,
        cacheWriteTokens: 5,
      },
    });

    // A caller that only knows input/output (e.g. the workflow path until T4).
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: { inputTokens: 150, outputTokens: 30 },
    });

    const metrics = readExecutionMetrics(rootPath());
    expect(metrics?.tokenUsage.inputTokens).toBe(150);
    expect(metrics?.tokenUsage.outputTokens).toBe(30);
    expect(metrics?.tokenUsage.cacheReadTokens).toBe(0); // legacy write resets cache it doesn't know about
  });

  it("drops malformed context samples instead of failing the read", () => {
    writeRaw({
      tokenUsage: { inputTokens: 1 },
      contextUsage: { usedTokens: 5, contextLimit: 10 }, // no modelId
    });
    expect(readExecutionMetrics(rootPath())?.contextUsage).toBeUndefined();
  });

  it("returns null for a missing or corrupt file", () => {
    expect(readExecutionMetrics(rootPath())).toBeNull();
    writeFileSync(metricsPath(), "{ not json", "utf-8");
    expect(readExecutionMetrics(rootPath())).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// One writer — merge semantics
// ---------------------------------------------------------------------------

describe("execution-metrics single-writer merge", () => {
  it("retains the context sample when a write omits it", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: { inputTokens: 1 },
      contextUsage: { usedTokens: 42, contextLimit: 200, modelId: "m" },
    });
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: { inputTokens: 2 },
    });

    expect(readExecutionMetrics(rootPath())?.contextUsage).toEqual({
      usedTokens: 42,
      contextLimit: 200,
      modelId: "m",
    });
  });

  it("replaces the context sample when a write provides one", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: { inputTokens: 1 },
      contextUsage: { usedTokens: 42, contextLimit: 200, modelId: "old" },
    });
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: { inputTokens: 2 },
      contextUsage: { usedTokens: 84, contextLimit: 272_000, modelId: "new" },
    });

    expect(readExecutionMetrics(rootPath())?.contextUsage).toEqual({
      usedTokens: 84,
      contextLimit: 272_000,
      modelId: "new",
    });
  });

  it("retains runtime and elapsedSeconds across usage-only writes", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: { inputTokens: 1 },
      runtime: "0h1m30s",
      elapsedSeconds: 90,
    });
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: { inputTokens: 2 },
    });

    const metrics = readExecutionMetrics(rootPath());
    expect(metrics?.runtime).toBe("0h1m30s");
    expect(metrics?.elapsedSeconds).toBe(90);
  });

  it("derives totalTokens from input + output (cache not double-counted)", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: {
        inputTokens: 1000,
        outputTokens: 100,
        cacheReadTokens: 900,
        cacheWriteTokens: 50,
      },
    });
    expect(readExecutionMetrics(rootPath())?.tokenUsage.totalTokens).toBe(1100);
  });

  it("sanitize negative and non-numeric fields", () => {
    writeExecutionMetrics({
      sessionRootPath: rootPath(),
      tokenUsage: {
        inputTokens: -5,
        outputTokens: Number.NaN,
        cacheReadTokens: 2.9,
      },
      contextUsage: { usedTokens: -1, contextLimit: -2, modelId: "m" },
    });
    const metrics = readExecutionMetrics(rootPath());
    expect(metrics?.tokenUsage).toEqual({
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 2,
      cacheWriteTokens: 0,
      totalTokens: 0,
    });
    expect(metrics?.contextUsage).toEqual({
      usedTokens: 0,
      contextLimit: 0,
      modelId: "m",
    });
  });
});

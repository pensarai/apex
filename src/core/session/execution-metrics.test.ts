import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { readExecutionMetrics, writeExecutionMetrics } from "./execution-metrics";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "execution-metrics-test-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("writeExecutionMetrics", () => {
  it("preserves larger token totals when requested", () => {
    writeExecutionMetrics({
      sessionRootPath: tmpDir,
      tokenUsage: {
        inputTokens: 100,
        outputTokens: 50,
        totalTokens: 160,
      },
    });

    const metrics = writeExecutionMetrics({
      sessionRootPath: tmpDir,
      tokenUsage: {
        inputTokens: 25,
        outputTokens: 10,
        totalTokens: 35,
      },
      preserveLargerTokenUsage: true,
    });

    expect(metrics.tokenUsage).toEqual({
      inputTokens: 100,
      outputTokens: 50,
      totalTokens: 160,
    });
    expect(readExecutionMetrics(tmpDir)?.tokenUsage).toEqual(metrics.tokenUsage);
  });

  it("replaces token totals by default", () => {
    writeExecutionMetrics({
      sessionRootPath: tmpDir,
      tokenUsage: {
        inputTokens: 100,
        outputTokens: 50,
        totalTokens: 160,
      },
    });

    const metrics = writeExecutionMetrics({
      sessionRootPath: tmpDir,
      tokenUsage: {
        inputTokens: 25,
        outputTokens: 10,
        totalTokens: 35,
      },
    });

    expect(metrics.tokenUsage).toEqual({
      inputTokens: 25,
      outputTokens: 10,
      totalTokens: 35,
    });
  });
});

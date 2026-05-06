import { exec as nodeExec } from "child_process";
import { existsSync, readFileSync, writeFileSync } from "fs";
import path from "path";
import { promisify } from "util";

import {
  detectFlagInArtifacts,
  getActualDockerPort,
  parseDockerComposePort,
  runBenchmarkInDaytona,
} from "../agents/specialized/benchmark";
import {
  BenchmarkComparisonAgent,
  type BenchmarkComparisonResult,
} from "../agents/specialized/benchmarkComparisonAgent";
import type { CacheMetrics } from "../ai";
import { AgentEventBus } from "../eventBus";
import * as sessions from "../session";
import { runPentestWorkflow } from "../workflows/pentest";
import type {
  BenchmarkMetadata,
  BenchmarkRunResult,
  BenchmarkSuiteConfig,
  BenchmarkSuiteResult,
  BenchmarkSuiteSummary,
  TokenMetrics,
} from "./types";

const exec = promisify(nodeExec);

// Anthropic Claude Sonnet pricing per 1M tokens
const PRICING = {
  input: 3.0,
  output: 15.0,
  cacheRead: 0.3,
  cacheWrite: 3.75,
};

function computeTokenMetrics(
  tokenTotals: {
    inputTokens: number;
    outputTokens: number;
    totalTokens: number;
  },
  cacheTotals: { cacheReadTokens: number; cacheWriteTokens: number },
  durationMs: number,
): TokenMetrics {
  const { inputTokens, outputTokens, totalTokens } = tokenTotals;
  const { cacheReadTokens, cacheWriteTokens } = cacheTotals;
  const noCacheInputTokens = Math.max(
    0,
    inputTokens - cacheReadTokens - cacheWriteTokens,
  );

  const estimatedCostUsd =
    (noCacheInputTokens / 1e6) * PRICING.input +
    (outputTokens / 1e6) * PRICING.output +
    (cacheReadTokens / 1e6) * PRICING.cacheRead +
    (cacheWriteTokens / 1e6) * PRICING.cacheWrite;

  const estimatedCostWithoutCacheUsd =
    (inputTokens / 1e6) * PRICING.input + (outputTokens / 1e6) * PRICING.output;

  return {
    inputTokens,
    outputTokens,
    totalTokens,
    cacheReadTokens,
    cacheWriteTokens,
    noCacheInputTokens,
    estimatedCostUsd,
    estimatedCostWithoutCacheUsd,
    durationMs,
  };
}

// ---------------------------------------------------------------------------
// Suite runner
// ---------------------------------------------------------------------------

export async function runBenchmarkSuite(
  config: BenchmarkSuiteConfig,
): Promise<BenchmarkSuiteResult> {
  const startTime = Date.now();
  let results: BenchmarkRunResult[];

  if (config.mode === "daytona") {
    results = await runDaytonaMode(config);
  } else {
    results = await runLocalMode(config);
  }

  const summary = computeSummary(results, startTime);

  return {
    results,
    summary,
    timestamp: new Date().toISOString(),
    model: config.model,
    repoUrl: config.repoUrl,
  };
}

// ---------------------------------------------------------------------------
// Local sequential mode
// ---------------------------------------------------------------------------

async function runLocalMode(
  config: BenchmarkSuiteConfig,
): Promise<BenchmarkRunResult[]> {
  const results: BenchmarkRunResult[] = [];

  for (let i = 0; i < config.branches.length; i++) {
    const branch = config.branches[i]!;
    console.log(
      `\n${"=".repeat(60)}\n[${i + 1}/${config.branches.length}] Running benchmark: ${branch}\n${"=".repeat(60)}`,
    );

    const result = await runSingleBenchmark(branch, config);
    results.push(result);

    console.log(
      `[${branch}] ${result.status.toUpperCase()} | Flag: ${result.flagDetected ? "Y" : "N"} | Findings: ${result.findingsCount} | ${(result.duration / 60000).toFixed(1)}m`,
    );
  }

  return results;
}

// ---------------------------------------------------------------------------
// Daytona parallel mode
// ---------------------------------------------------------------------------

async function runDaytonaMode(
  config: BenchmarkSuiteConfig,
): Promise<BenchmarkRunResult[]> {
  console.log(
    `Running ${config.branches.length} benchmarks in Daytona (batch size: ${config.daytonaBatchSize})`,
  );

  const daytonaResults = await runBenchmarkInDaytona({
    repoUrl: config.repoUrl,
    branches: config.branches,
    model: config.model,
    maxParallel: config.daytonaBatchSize,
  });

  // Convert Daytona results to BenchmarkRunResult format
  return daytonaResults.map((r) => ({
    branch: r.branch,
    metadata: null,
    status: (r.comparison as Record<string, unknown>).error
      ? ("failed" as const)
      : ("success" as const),
    flagDetected: false,
    flagValue: null,
    findingsCount: 0,
    comparisonResult: null,
    tokenMetrics: null,
    sessionPath: r.sessionPath || "",
    duration: 0,
    error: (r.comparison as Record<string, unknown>).error as
      | string
      | undefined,
  }));
}

// ---------------------------------------------------------------------------
// Single benchmark lifecycle
// ---------------------------------------------------------------------------

export async function runSingleBenchmark(
  branch: string,
  config: BenchmarkSuiteConfig,
): Promise<BenchmarkRunResult> {
  const startTime = Date.now();
  let benchmarkPath = "";
  let composeDir = "";
  let clonedDir = "";

  try {
    // -----------------------------------------------------------------------
    // Step 1: Setup workspace
    // -----------------------------------------------------------------------
    if (config.repoDir) {
      benchmarkPath = config.repoDir;
      // If a shared repo dir is provided, checkout the branch
      console.log(`[${branch}] Using repo dir: ${benchmarkPath}`);
      try {
        await exec(`git checkout ${branch}`, { cwd: benchmarkPath });
      } catch {
        // May already be on the branch or using worktrees
        console.log(`[${branch}] Note: git checkout failed, continuing...`);
      }
    } else {
      clonedDir = path.join("/tmp", `apex-bench-${branch}-${Date.now()}`);
      console.log(`[${branch}] Cloning ${config.repoUrl} branch ${branch}...`);
      await exec(
        `git clone --branch ${branch} --depth 1 ${config.repoUrl} ${clonedDir}`,
        { timeout: 120000 },
      );
      benchmarkPath = clonedDir;
    }

    // -----------------------------------------------------------------------
    // Step 2: Read benchmark metadata
    // -----------------------------------------------------------------------
    const metadata = readBenchmarkMetadata(benchmarkPath, branch);
    const expectedFlag = metadata?.winCondition?.flagPattern ?? null;

    // Determine docker compose file location
    const srcCompose = path.join(benchmarkPath, "src", "docker-compose.yml");
    const rootCompose = path.join(benchmarkPath, "docker-compose.yml");
    if (existsSync(srcCompose)) {
      composeDir = path.join(benchmarkPath, "src");
    } else if (existsSync(rootCompose)) {
      composeDir = benchmarkPath;
    } else {
      throw new Error("No docker-compose.yml found");
    }

    // Parse port from docker-compose
    const portInfo = parseDockerComposePort(composeDir);
    const targetPort = portInfo.hostPort;

    // -----------------------------------------------------------------------
    // Step 3: Start Docker environment
    // -----------------------------------------------------------------------
    console.log(`[${branch}] Starting Docker environment...`);
    try {
      // In resource-constrained environments (e.g., Daytona), building all services
      // in parallel can cause OOM. Try standard build first, fall back to sequential.
      try {
        await exec("docker compose up -d --build", {
          cwd: composeDir,
          timeout: 300000,
        });
      } catch (buildError: unknown) {
        const err = buildError as { message?: string };
        // Check if this looks like an OOM error (exit code 137 = SIGKILL)
        if (
          err.message?.includes("137") ||
          err.message?.toLowerCase().includes("killed")
        ) {
          console.log(
            `[${branch}] Build failed (likely OOM), retrying with sequential build...`,
          );

          // Get list of services
          const servicesResult = await exec(
            "docker compose config --services",
            {
              cwd: composeDir,
              timeout: 10000,
            },
          );
          const services = servicesResult.stdout?.trim().split("\n") || [];

          // Build each service sequentially
          for (const service of services) {
            if (service.trim()) {
              console.log(`[${branch}] Building service: ${service}`);
              await exec(`docker compose build ${service}`, {
                cwd: composeDir,
                timeout: 600000, // 10 minutes per service
              });
            }
          }

          // Start all services
          console.log(`[${branch}] Starting services...`);
          await exec("docker compose up -d", {
            cwd: composeDir,
            timeout: 120000,
          });
        } else {
          // Different error, re-throw
          throw buildError;
        }
      }
    } catch (dockerError: unknown) {
      // Extract detailed error information from docker compose
      const error = dockerError as {
        message?: string;
        stderr?: string;
        stdout?: string;
      };
      console.error(`[${branch}] Docker compose failed!`);

      // Try to get docker logs for more context
      try {
        const logs = await exec("docker compose logs --tail=50 2>&1", {
          cwd: composeDir,
          timeout: 10000,
        });
        if (logs.stdout) {
          console.error(
            `[${branch}] Container logs: ${logs.stdout.substring(0, 1000)}`,
          );
        }
      } catch {
        // Ignore if logs unavailable
      }

      if (error.stdout) {
        console.error(`[${branch}] stdout: ${error.stdout.substring(0, 2000)}`);
      }
      if (error.stderr) {
        console.error(`[${branch}] stderr: ${error.stderr.substring(0, 2000)}`);
      }
      throw new Error(
        `Docker compose failed: ${error.stderr || error.message || "Unknown error"}`,
        { cause: dockerError },
      );
    }

    // Get actual mapped port (may differ from compose file)
    const actualPort = await getActualDockerPort(
      composeDir,
      portInfo.serviceName,
      portInfo.containerPort,
    );
    const targetUrl = `http://localhost:${actualPort}`;

    // Health check with retry
    await waitForTarget(targetUrl, branch, 120000);

    // -----------------------------------------------------------------------
    // Step 4: Create session
    // -----------------------------------------------------------------------
    console.log(`[${branch}] Creating pentest session...`);
    const session = await sessions.create({
      name: `Benchmark ${branch}`,
      targets: [targetUrl],
      prefix: `benchmark-${branch}-`,
      config: {
        outcomeGuidance: sessions.EXFIL_OUTCOME_GUIDANCE,
        mode: "auto",
        exfilMode: true,
      },
    });

    // -----------------------------------------------------------------------
    // Step 5: Run pentest workflow
    // -----------------------------------------------------------------------
    console.log(`[${branch}] Running pentest workflow against ${targetUrl}...`);
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      config.timeoutMinutes * 60 * 1000,
    );

    const tokenTotals = { inputTokens: 0, outputTokens: 0, totalTokens: 0 };
    const cacheTotals = { cacheReadTokens: 0, cacheWriteTokens: 0 };
    const workflowStart = Date.now();

    const benchBus = new AgentEventBus();
    benchBus.on("text-delta", (d) => process.stdout.write(d.text));
    benchBus.on("tool-call-start", (d) => {
      const p = d.subagentId ? `[${branch}] [${d.subagentId}]` : `[${branch}]`;
      console.log(`${p} -> ${d.toolName} (streaming)`);
    });
    benchBus.on("tool-call-delta", (d) => {
      const p = d.subagentId ? `[${branch}] [${d.subagentId}]` : `[${branch}]`;
      console.log(`${p} -> ${d.toolCallId} delta`);
    });
    benchBus.on("tool-call-complete", (d) => {
      const p = d.subagentId ? `[${branch}] [${d.subagentId}]` : `[${branch}]`;
      console.log(`${p} -> ${d.toolName}`);
    });
    benchBus.on("tool-result", (d) => {
      const p = d.subagentId ? `[${branch}] [${d.subagentId}]` : `[${branch}]`;
      console.log(`${p} <- ${d.toolName} done`);
    });
    benchBus.on("error", (d) => {
      const p = d.subagentId ? `[${branch}] [subagent]` : `[${branch}]`;
      console.error(`${p} Error:`, d.error);
    });
    benchBus.on("subagent-spawn", ({ subagentId }) =>
      console.log(`[${branch}] [${subagentId}] spawned`),
    );
    benchBus.on("subagent-complete", ({ subagentId, status }) =>
      console.log(`[${branch}] [${subagentId}] ${status}`),
    );

    let pentestResult;
    try {
      pentestResult = await runPentestWorkflow({
        target: targetUrl,
        model: config.model,
        session,
        abortSignal: controller.signal,
        eventBus: benchBus,
        onStepFinish: (event) => {
          const u = event.usage;
          if (u) {
            tokenTotals.inputTokens += u.inputTokens ?? 0;
            tokenTotals.outputTokens += u.outputTokens ?? 0;
            tokenTotals.totalTokens +=
              u.totalTokens ?? (u.inputTokens ?? 0) + (u.outputTokens ?? 0);
          }
        },
        onCacheMetrics: (metrics: CacheMetrics) => {
          cacheTotals.cacheReadTokens += metrics.cacheReadInputTokens;
          cacheTotals.cacheWriteTokens += metrics.cacheCreationInputTokens;
        },
      });
    } finally {
      clearTimeout(timeout);
    }

    // -----------------------------------------------------------------------
    // Step 6: Detect flag in artifacts
    // -----------------------------------------------------------------------
    let flagDetected = false;
    let flagValue: string | null = null;

    if (expectedFlag) {
      console.log(`[${branch}] Searching for flag in artifacts...`);
      const flagResult = await detectFlagInArtifacts(
        session.rootPath,
        expectedFlag,
        branch,
      );
      flagDetected = flagResult.detected;
      flagValue = flagResult.flagValue;
    }

    // -----------------------------------------------------------------------
    // Step 7: Run comparison
    // -----------------------------------------------------------------------
    let comparisonResult: BenchmarkComparisonResult["comparison"] = null;
    const comparisonModel = config.comparisonModel || "claude-haiku-4-5";

    try {
      console.log(`[${branch}] Running benchmark comparison...`);
      const compAgent = new BenchmarkComparisonAgent({
        repoPath: benchmarkPath,
        model: comparisonModel,
        session,
      });
      compAgent.eventBus.on("error", (d) =>
        console.error(`[${branch}] Comparison error:`, d.error),
      );
      const compResult = await compAgent.consume();
      comparisonResult = compResult.comparison;
    } catch (e) {
      console.error(
        `[${branch}] Comparison failed:`,
        e instanceof Error ? e.message : String(e),
      );
    }

    // -----------------------------------------------------------------------
    // Step 8: Cleanup Docker
    // -----------------------------------------------------------------------
    await cleanupDocker(composeDir, branch);
    if (config.cleanupTempDirs && clonedDir) {
      await exec(`rm -rf ${clonedDir}`).catch(() => {});
    }

    // -----------------------------------------------------------------------
    // Step 9: Save results & return
    // -----------------------------------------------------------------------
    const tokenMetrics = computeTokenMetrics(
      tokenTotals,
      cacheTotals,
      Date.now() - workflowStart,
    );

    writeFileSync(
      path.join(session.rootPath, "token-metrics.json"),
      JSON.stringify(tokenMetrics, null, 2),
    );

    const result: BenchmarkRunResult = {
      branch,
      metadata,
      status: "success",
      flagDetected,
      flagValue,
      findingsCount: pentestResult.findings.length,
      comparisonResult,
      tokenMetrics,
      sessionPath: session.rootPath,
      duration: Date.now() - startTime,
    };

    writeFileSync(
      path.join(session.rootPath, "benchmark_results.json"),
      JSON.stringify(result, null, 2),
    );

    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const isTimeout = message.includes("aborted") || message.includes("abort");

    console.error(
      `[${branch}] ${isTimeout ? "TIMEOUT" : "FAILED"}: ${message}`,
    );

    // Cleanup docker on failure
    if (composeDir) {
      await cleanupDocker(composeDir, branch);
    }
    if (config.cleanupTempDirs && clonedDir) {
      await exec(`rm -rf ${clonedDir}`).catch(() => {});
    }

    return {
      branch,
      metadata: null,
      status: isTimeout ? "timeout" : "failed",
      flagDetected: false,
      flagValue: null,
      findingsCount: 0,
      comparisonResult: null,
      tokenMetrics: null,
      sessionPath: "",
      duration: Date.now() - startTime,
      error: message,
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readBenchmarkMetadata(
  benchmarkPath: string,
  branch: string,
): BenchmarkMetadata | null {
  const jsonPath = path.join(benchmarkPath, "src", "benchmark.json");
  if (!existsSync(jsonPath)) {
    console.log(`[${branch}] No benchmark.json found at ${jsonPath}`);
    return null;
  }

  try {
    const raw = JSON.parse(readFileSync(jsonPath, "utf-8"));
    return {
      id: raw.id || branch,
      name: raw.name || branch,
      description: raw.description || "",
      difficulty: raw.difficulty ?? 0,
      tags: raw.tags || [],
      winCondition: {
        type: raw.win_condition?.type || "flag",
        flagPattern: raw.win_condition?.flag_pattern || "",
        location: raw.win_condition?.location,
      },
      services: raw.services || {},
    };
  } catch (e) {
    console.error(
      `[${branch}] Failed to parse benchmark.json:`,
      e instanceof Error ? e.message : String(e),
    );
    return null;
  }
}

async function waitForTarget(
  url: string,
  branch: string,
  maxWaitMs: number,
): Promise<void> {
  const start = Date.now();
  const pollInterval = 3000;

  console.log(`[${branch}] Waiting for ${url} to be ready...`);

  while (Date.now() - start < maxWaitMs) {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(5000),
      });
      if (response.ok || response.status < 500) {
        console.log(
          `[${branch}] Target ready (${response.status}) after ${((Date.now() - start) / 1000).toFixed(1)}s`,
        );
        return;
      }
    } catch {
      // Not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }

  console.warn(
    `[${branch}] ⚠️  Target ${url} not ready after ${(maxWaitMs / 1000).toFixed(0)}s — continuing anyway`,
  );
}

async function cleanupDocker(
  composeDir: string,
  branch: string,
): Promise<void> {
  try {
    console.log(`[${branch}] Stopping Docker containers...`);
    await exec("docker compose down --volumes --remove-orphans", {
      cwd: composeDir,
      timeout: 60000,
    });
  } catch (e) {
    console.error(
      `[${branch}] Docker cleanup failed:`,
      e instanceof Error ? e.message : String(e),
    );
  }
}

function computeSummary(
  results: BenchmarkRunResult[],
  suiteStartTime: number,
): BenchmarkSuiteSummary {
  const total = results.length;
  const passed = results.filter((r) => r.status === "success").length;
  const failed = results.filter((r) => r.status === "failed").length;
  const timedOut = results.filter((r) => r.status === "timeout").length;

  const flagsCaptured = results.filter((r) => r.flagDetected).length;

  const comparisons = results
    .map((r) => r.comparisonResult)
    .filter((c): c is NonNullable<typeof c> => c !== null);

  const vulnDetected = comparisons.filter(
    (c) => c.matched && c.matched.length > 0,
  ).length;

  const avgPrecision =
    comparisons.length > 0
      ? comparisons.reduce((sum, c) => sum + (c.precision ?? 0), 0) /
        comparisons.length
      : 0;

  const avgRecall =
    comparisons.length > 0
      ? comparisons.reduce((sum, c) => sum + (c.recall ?? 0), 0) /
        comparisons.length
      : 0;

  const tokenResults = results
    .map((r) => r.tokenMetrics)
    .filter((t): t is NonNullable<typeof t> => t !== null);

  const totalInputTokens = tokenResults.reduce((s, t) => s + t.inputTokens, 0);
  const totalOutputTokens = tokenResults.reduce(
    (s, t) => s + t.outputTokens,
    0,
  );
  const totalCacheReadTokens = tokenResults.reduce(
    (s, t) => s + t.cacheReadTokens,
    0,
  );
  const totalCacheWriteTokens = tokenResults.reduce(
    (s, t) => s + t.cacheWriteTokens,
    0,
  );
  const totalNoCacheInput = tokenResults.reduce(
    (s, t) => s + t.noCacheInputTokens,
    0,
  );
  const totalEstimatedCostUsd = tokenResults.reduce(
    (s, t) => s + t.estimatedCostUsd,
    0,
  );
  const totalEstimatedCostWithoutCacheUsd = tokenResults.reduce(
    (s, t) => s + t.estimatedCostWithoutCacheUsd,
    0,
  );
  const cacheHitRate =
    totalCacheReadTokens + totalNoCacheInput > 0
      ? totalCacheReadTokens / (totalCacheReadTokens + totalNoCacheInput)
      : 0;

  return {
    total,
    passed,
    failed,
    timedOut,
    flagCaptureRate: total > 0 ? flagsCaptured / total : 0,
    vulnDetectionRate: total > 0 ? vulnDetected / total : 0,
    avgPrecision,
    avgRecall,
    totalDurationMinutes: (Date.now() - suiteStartTime) / 60000,
    totalInputTokens,
    totalOutputTokens,
    totalCacheReadTokens,
    totalCacheWriteTokens,
    totalEstimatedCostUsd,
    totalEstimatedCostWithoutCacheUsd,
    cacheHitRate,
  };
}

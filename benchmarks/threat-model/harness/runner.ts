#!/usr/bin/env bun

/**
 * Threat Model Benchmark Runner
 *
 * Evaluates Apex's threat modelling quality by running runThreatModelWorkflow()
 * against known test applications and scoring the output.
 *
 * Usage:
 *   bun run benchmarks/threat-model/harness/runner.ts [options]
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import path from "path";
import { runThreatModelWorkflow } from "../../../src/core/workflows/threatModel";
import { parseConfig } from "./config";
import { normalizeGroundTruth } from "./types";
import type {
  AppResult,
  AppScorecard,
  BenchmarkConfig,
  BehavioralMetrics,
  RegressionResult,
  SuiteResult,
} from "./types";
import { TraceCollector } from "./trace-collector";
import { parseThreatModelMarkdown } from "./markdown-parser";
import { validateStructural } from "./validators/structural";
import { validateGrounding } from "./validators/grounding";
import { validateAntiPatterns } from "./validators/antipattern";
import { validateDiscovery } from "./validators/discovery";
import { judgeAttackPaths } from "./judges/attack-path-judge";
import { judgeEffectiveness } from "./judges/effectiveness-judge";
import { aggregateAppScores, aggregateHeadlineMetrics } from "./scoring/aggregator";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function loadGroundTruth(appDir: string) {
  const gtPath = path.join(appDir, "ground-truth.json");
  if (!existsSync(gtPath)) {
    throw new Error(`Ground truth not found: ${gtPath}`);
  }
  const raw = JSON.parse(readFileSync(gtPath, "utf-8"));
  return normalizeGroundTruth(raw);
}

function writeJSON(filePath: string, data: unknown): void {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// ---------------------------------------------------------------------------
// Run Single App
// ---------------------------------------------------------------------------

async function runApp(
  appId: string,
  config: BenchmarkConfig,
  runId: string,
): Promise<AppResult> {
  const appDir = path.join(config.appsDir, appId);
  const codebasePath = path.join(appDir, "src");
  const appResultsDir = path.join(config.resultsDir, runId, appId);
  const outputPath = path.join(appResultsDir, "output.md");

  console.log(`\n${"=".repeat(60)}`);
  console.log(`Running: ${appId}`);
  console.log(`Codebase: ${codebasePath}`);
  console.log(`${"=".repeat(60)}`);

  const gt = loadGroundTruth(appDir);

  // Set up trace capture and abort controller
  const trace = new TraceCollector(config.model as string);
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), config.timeout);

  // Live logging — stream agent activity to stdout
  let stepCount = 0;
  let toolsUsed = 0;
  trace.eventBus.on("step-finish", () => {
    stepCount++;
    if (stepCount % 5 === 0) {
      console.log(`  [step ${stepCount}] ${toolsUsed} tool calls so far`);
    }
  });
  trace.eventBus.on("tool-call-start", (e) => {
    toolsUsed++;
    const args = e.args as Record<string, unknown> | undefined;
    let detail = "";
    if (e.toolName === "read_file" || e.toolName === "create_file") {
      detail = ` → ${args?.file_path ?? args?.path ?? ""}`;
    } else if (e.toolName === "grep") {
      detail = ` → "${args?.pattern ?? ""}"`;
    } else if (e.toolName === "execute_command") {
      const cmd = String(args?.command ?? "").slice(0, 80);
      detail = ` → ${cmd}`;
    } else if (e.toolName === "list_files") {
      detail = ` → ${args?.path ?? ""}`;
    }
    console.log(`  [tool] ${e.toolName}${detail}`);
  });
  trace.eventBus.on("subagent-spawn", (e) => {
    console.log(`  [subagent] spawned: ${e.name ?? e.subagentId}`);
  });
  trace.eventBus.on("subagent-complete", (e) => {
    console.log(`  [subagent] ${e.subagentId}: ${e.status}`);
  });
  trace.eventBus.on("error", (e) => {
    console.error(`  [error] ${e.error instanceof Error ? e.error.message : String(e.error)}`);
  });

  let behavioral: BehavioralMetrics;
  let outputMd = "";

  try {
    // Run the threat model workflow
    console.log(`  Model: ${config.model}`);
    console.log(`  Timeout: ${config.timeout / 1000}s`);
    console.log(`  Starting threat model generation...\n`);

    await runThreatModelWorkflow({
      codebasePath,
      outputPath,
      model: config.model,
      eventBus: trace.eventBus,
      abortSignal: controller.signal,
      authConfig: config.authConfig,
    });

    clearTimeout(timeoutHandle);
    behavioral = trace.computeMetrics();

    // Check output file was written
    if (existsSync(outputPath)) {
      behavioral.completionSuccess = true;
      outputMd = readFileSync(outputPath, "utf-8");
      console.log(
        `  Output written: ${outputPath} (${outputMd.length} chars)`,
      );
    } else {
      console.log(`  WARNING: Output file not written`);
    }

    // Log token usage
    const tok = behavioral.tokens;
    console.log(`\n  Token Usage:`);
    console.log(`    Input:        ${tok.inputTokens.toLocaleString()}`);
    console.log(`    Output:       ${tok.outputTokens.toLocaleString()}`);
    console.log(`    Cache read:   ${tok.cacheReadTokens.toLocaleString()}`);
    console.log(`    Cache write:  ${tok.cacheWriteTokens.toLocaleString()}`);
    console.log(`    Total:        ${tok.totalTokens.toLocaleString()}`);
    console.log(`    Est. cost:    $${tok.estimatedCostUsd.toFixed(4)}`);
  } catch (error) {
    clearTimeout(timeoutHandle);
    behavioral = trace.computeMetrics();
    const msg =
      error instanceof Error ? error.message : String(error);
    const isTimeout = msg.includes("abort") || msg.includes("cancel");

    console.error(
      `  FAILED: ${isTimeout ? "Timeout" : msg}`,
    );

    // Still try to read partial output
    if (existsSync(outputPath)) {
      outputMd = readFileSync(outputPath, "utf-8");
    }

    const failedScorecard: AppScorecard = {
      appId,
      status: isTimeout ? "timeout" : "failed",
      overall: 0,
      structural: null,
      grounding: null,
      antipattern: null,
      discovery: null,
      attackPathDepth: null,
      effectiveness: null,
      behavioral,
      error: msg,
    };

    // Write trace even on failure
    writeJSON(path.join(appResultsDir, "trace.json"), trace.export());
    writeJSON(path.join(appResultsDir, "scores.json"), failedScorecard);

    return { appId, scorecard: failedScorecard, trace: trace.export() };
  }

  // Parse the output markdown
  console.log(`  Parsing output...`);
  const parsed = parseThreatModelMarkdown(outputMd);
  console.log(
    `  Sections found: ${parsed.sectionsFound.length}`,
  );
  console.log(
    `  Attack paths: ${parsed.attackPaths.length}`,
  );
  console.log(
    `  Security controls: ${parsed.securityControls.length}`,
  );

  // Run automated validators
  console.log(`  Running structural validation...`);
  const structural = validateStructural(parsed, gt);
  console.log(`    Score: ${(structural.score * 100).toFixed(1)}%`);

  console.log(`  Running grounding validation...`);
  const grounding = validateGrounding(parsed, codebasePath);
  console.log(`    Score: ${(grounding.score * 100).toFixed(1)}%`);

  // Anti-pattern validation (automated part runs always)
  console.log(`  Running anti-pattern validation...`);
  const antipattern = validateAntiPatterns(parsed, trace.export());
  console.log(`    Score: ${(antipattern.score * 100).toFixed(1)}%`);

  // Phase 2 validators (LLM judges)
  let discovery = null;
  let attackPathDepth = null;
  let effectiveness = null;

  if (!config.fast) {
    console.log(`  Running discovery validation (LLM)...`);
    discovery = await validateDiscovery(
      parsed,
      gt,
      config.judgeModel,
      config.authConfig,
    );
    console.log(`    Vuln recall: ${(discovery.vulnerabilityRecall * 100).toFixed(1)}%`);
    console.log(`    FP rate: ${(discovery.falsePositiveRate * 100).toFixed(1)}%`);
    if (discovery.missedVulnerabilities.length > 0) {
      console.log(`    Missed: ${discovery.missedVulnerabilities.join(", ")}`);
    }

    if (parsed.attackPaths.length > 0) {
      console.log(`  Judging attack paths (LLM)...`);
      attackPathDepth = await judgeAttackPaths(
        parsed.attackPaths,
        appDir,
        gt,
        config.judgeModel,
        config.authConfig,
      );
      console.log(`    Avg score: ${attackPathDepth.score.toFixed(2)}/5`);
    }

    console.log(`  Judging effectiveness (LLM)...`);
    effectiveness = await judgeEffectiveness(
      outputMd,
      gt,
      config.judgeModel,
      config.authConfig,
    );
    console.log(`    Avg score: ${effectiveness.score.toFixed(2)}/5`);
  }

  // Aggregate scores
  const scorecard = aggregateAppScores({
    appId,
    gt,
    structural,
    grounding,
    antipattern,
    discovery,
    attackPathDepth,
    effectiveness,
    behavioral,
  });

  console.log(`  Overall score: ${scorecard.overall.toFixed(1)}/100`);

  // Write results
  writeJSON(path.join(appResultsDir, "scores.json"), scorecard);
  writeJSON(path.join(appResultsDir, "trace.json"), trace.export());

  return { appId, scorecard, trace: trace.export() };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const config = parseConfig(process.argv.slice(2));
  const runId = `tm-bench-${timestamp()}`;

  console.log(`\nThreat Model Benchmark Runner`);
  console.log(`${"=".repeat(60)}`);
  console.log(`Run ID:     ${runId}`);
  console.log(`Model:      ${config.model}`);
  console.log(`Apps:       ${config.apps.join(", ")}`);
  console.log(`Fast mode:  ${config.fast}`);
  console.log(`Repeats:    ${config.repeats}`);
  console.log(`Apps dir:   ${config.appsDir}`);
  console.log(`Results:    ${path.join(config.resultsDir, runId)}`);

  const results: AppResult[] = [];

  for (const appId of config.apps) {
    for (let repeat = 0; repeat < config.repeats; repeat++) {
      const effectiveRunId =
        config.repeats > 1 ? `${runId}/repeat-${repeat + 1}` : runId;

      try {
        const result = await runApp(appId, config, effectiveRunId);
        results.push(result);
      } catch (error) {
        console.error(
          `Unexpected error on ${appId}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // Aggregate across all apps
  const scorecards = results.map((r) => r.scorecard);
  const headline = aggregateHeadlineMetrics(scorecards);
  const perApp: Record<string, AppScorecard> = {};
  for (const r of results) {
    perApp[r.appId] = r.scorecard;
  }

  const summary: SuiteResult = {
    runId,
    model: config.model as string,
    timestamp: new Date().toISOString(),
    config: {
      apps: config.apps,
      fast: config.fast,
      repeats: config.repeats,
    },
    headline,
    perApp,
  };

  // Load and compare with previous run if requested
  if (config.compareWith) {
    const prevPath = path.join(
      config.resultsDir,
      config.compareWith,
      "summary.json",
    );
    if (existsSync(prevPath)) {
      try {
        const prev: SuiteResult = JSON.parse(
          readFileSync(prevPath, "utf-8"),
        );
        const delta = headline.overallScore - prev.headline.overallScore;
        const significantChanges: RegressionResult["significantChanges"] =
          [];

        for (const appId of Object.keys(perApp)) {
          const curr = perApp[appId];
          const prevApp = prev.perApp[appId];
          if (!prevApp) continue;

          const overallDelta = curr.overall - prevApp.overall;
          if (Math.abs(overallDelta) > 5) {
            significantChanges.push({
              metric: "overall",
              app: appId,
              delta: overallDelta,
              direction: overallDelta > 0 ? "improvement" : "regression",
            });
          }
        }

        summary.regression = {
          previousRunId: config.compareWith,
          overallDelta: delta,
          significantChanges,
        };
      } catch {
        console.error(
          `Could not load previous run: ${prevPath}`,
        );
      }
    } else {
      console.error(`Previous run not found: ${prevPath}`);
    }
  }

  // Write suite summary
  const summaryPath = path.join(config.resultsDir, runId, "summary.json");
  writeJSON(summaryPath, summary);

  // Print summary
  console.log(`\n${"=".repeat(60)}`);
  console.log(`RESULTS: ${runId}`);
  console.log(`${"=".repeat(60)}`);
  console.log(`\nHeadline Metrics:`);
  console.log(
    `  Overall Score:      ${headline.overallScore.toFixed(1)}/100`,
  );
  console.log(
    `  Vuln Recall:        ${(headline.vulnerabilityRecall * 100).toFixed(1)}%`,
  );
  console.log(
    `  False Positive Rate: ${(headline.falsePositiveRate * 100).toFixed(1)}%`,
  );
  console.log(
    `  Grounding Score:    ${(headline.groundingScore * 100).toFixed(1)}%`,
  );
  console.log(
    `  Total Cost:          $${headline.totalCostUsd.toFixed(4)}`,
  );

  console.log(`\nPer-App Results:`);
  console.log(
    `  ${"App".padEnd(14)} ${"Status".padEnd(10)} ${"Overall".padEnd(9)} ${"Struct".padEnd(8)} ${"Ground".padEnd(8)} ${"Steps".padEnd(7)} ${"Tokens".padEnd(10)} ${"Cost".padEnd(8)}`,
  );
  console.log(`  ${"-".repeat(74)}`);
  for (const r of results) {
    const s = r.scorecard;
    const tok = s.behavioral.tokens;
    console.log(
      `  ${s.appId.padEnd(14)} ${s.status.padEnd(10)} ${s.overall.toFixed(1).padStart(6)}    ${((s.structural?.score ?? 0) * 100).toFixed(0).padStart(4)}%   ${((s.grounding?.score ?? 0) * 100).toFixed(0).padStart(4)}%   ${String(s.behavioral.totalSteps).padStart(5)}  ${(tok?.totalTokens ?? 0).toLocaleString().padStart(9)}  $${(tok?.estimatedCostUsd ?? 0).toFixed(4)}`,
    );
  }

  if (summary.regression) {
    console.log(`\nRegression vs ${summary.regression.previousRunId}:`);
    console.log(
      `  Overall delta: ${summary.regression.overallDelta > 0 ? "+" : ""}${summary.regression.overallDelta.toFixed(1)}`,
    );
    for (const change of summary.regression.significantChanges) {
      const arrow = change.direction === "improvement" ? "+" : "";
      console.log(
        `  ${change.app} ${change.metric}: ${arrow}${change.delta.toFixed(1)} (${change.direction})`,
      );
    }
  }

  console.log(`\nResults written to: ${summaryPath}`);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});

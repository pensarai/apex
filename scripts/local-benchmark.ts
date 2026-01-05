#!/usr/bin/env tsx

import { readdirSync, statSync, existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import path from "path";
import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import type { AIModel } from "../src/core/ai";
import pLimit from "p-limit";
import type { BenchmarkResults } from "../src/core/agent/benchmark/types";
import { parseDockerComposePort, getActualDockerPort } from "../src/core/agent/benchmark/docker-utils";
import { Session } from "../src/core/session";
import { runStreamlinedPentest } from "../src/core/agent/thoroughPentestAgent/streamlined";
import {
  extractFlagFromRepo,
  detectFlagInArtifacts,
  extractPACEFlags,
  detectMultipleFlagsInArtifacts,
} from "../src/core/agent/benchmark/flag-detector";
import type {
  ExecuteCommandOpts,
  ExecuteCommandResult,
  HttpRequestOpts,
  HttpRequestResult,
} from "../src/core/agent/tools";

const exec = promisify(nodeExec);

interface PocRunResult {
  pocFile: string;
  pocName: string;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  duration: number;
  success: boolean;
  error?: string;
}

/**
 * Re-run all POC scripts in a session and save their outputs
 */
async function rerunAllPocs(
  sessionPath: string,
  benchmarkName: string,
  targetUrl: string
): Promise<{ total: number; passed: number; failed: number; results: PocRunResult[] }> {
  const pocsDir = path.join(sessionPath, "pocs");
  const logsDir = path.join(pocsDir, "logs");

  // Check if pocs directory exists
  if (!existsSync(pocsDir)) {
    console.log(`[${benchmarkName}] 📁 No POCs directory found, skipping POC re-run`);
    return { total: 0, passed: 0, failed: 0, results: [] };
  }

  // Create logs directory
  mkdirSync(logsDir, { recursive: true });

  // Find all POC files
  const files = readdirSync(pocsDir);
  const pocFiles = files.filter(
    (f) => f.endsWith(".sh") || f.endsWith(".html")
  );

  if (pocFiles.length === 0) {
    console.log(`[${benchmarkName}] 📁 No POC files found in ${pocsDir}`);
    return { total: 0, passed: 0, failed: 0, results: [] };
  }

  console.log(`[${benchmarkName}] 🔄 Re-running ${pocFiles.length} POC(s)...`);

  const results: PocRunResult[] = [];
  let passed = 0;
  let failed = 0;

  for (const pocFile of pocFiles) {
    const pocPath = path.join(pocsDir, pocFile);
    const pocName = pocFile.replace(/\.(sh|html)$/, "");
    const logFileName = `${pocName}-${new Date().toISOString().replace(/[:.]/g, "-")}.log`;
    const logPath = path.join(logsDir, logFileName);

    if (pocFile.endsWith(".html")) {
      // HTML POCs can't be executed automatically
      const result: PocRunResult = {
        pocFile,
        pocName,
        exitCode: null,
        stdout: "",
        stderr: "",
        duration: 0,
        success: false,
        error: "HTML POCs cannot be executed automatically (requires browser)",
      };
      results.push(result);

      const logContent = `POC: ${pocFile}
Type: HTML
Status: SKIPPED (HTML POCs require manual browser execution)
Timestamp: ${new Date().toISOString()}
`;
      writeFileSync(logPath, logContent);
      console.log(`[${benchmarkName}]   ⏭️  ${pocFile} (HTML - skipped)`);
      continue;
    }

    // Execute bash POC
    const startTime = Date.now();
    let result: PocRunResult;

    try {
      // Make script executable
      await exec(`chmod +x "${pocPath}"`);

      // Run the POC with a timeout of 2 minutes
      // Set TARGET environment variable to override any hardcoded target
      const { stdout, stderr } = await exec(`bash "${pocPath}"`, {
        timeout: 120000,
        env: {
          ...process.env,
          TARGET: targetUrl,
        },
        cwd: pocsDir,
      });

      const duration = Date.now() - startTime;
      result = {
        pocFile,
        pocName,
        exitCode: 0,
        stdout,
        stderr,
        duration,
        success: true,
      };
      passed++;
      console.log(`[${benchmarkName}]   ✅ ${pocFile} (${(duration / 1000).toFixed(1)}s)`);
    } catch (error: any) {
      const duration = Date.now() - startTime;
      result = {
        pocFile,
        pocName,
        exitCode: error.code ?? 1,
        stdout: error.stdout || "",
        stderr: error.stderr || error.message || "",
        duration,
        success: false,
        error: error.message,
      };
      failed++;
      console.log(`[${benchmarkName}]   ❌ ${pocFile} (exit code: ${result.exitCode})`);
    }

    results.push(result);

    // Save log file
    const logContent = `POC: ${pocFile}
Type: Bash Script
Exit Code: ${result.exitCode}
Success: ${result.success}
Duration: ${result.duration}ms
Timestamp: ${new Date().toISOString()}
Target: ${targetUrl}

${"=".repeat(60)}
STDOUT:
${"=".repeat(60)}
${result.stdout || "(empty)"}

${"=".repeat(60)}
STDERR:
${"=".repeat(60)}
${result.stderr || "(empty)"}

${result.error ? `\n${"=".repeat(60)}\nERROR:\n${"=".repeat(60)}\n${result.error}\n` : ""}
`;
    writeFileSync(logPath, logContent);
  }

  // Save summary
  const summaryPath = path.join(logsDir, "poc-run-summary.json");
  const summary = {
    timestamp: new Date().toISOString(),
    benchmarkName,
    targetUrl,
    total: pocFiles.length,
    passed,
    failed,
    skipped: pocFiles.filter((f) => f.endsWith(".html")).length,
    results: results.map((r) => ({
      pocFile: r.pocFile,
      pocName: r.pocName,
      exitCode: r.exitCode,
      success: r.success,
      duration: r.duration,
      error: r.error,
    })),
  };
  writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

  console.log(`[${benchmarkName}] 📊 POC Re-run Summary: ${passed} passed, ${failed} failed, ${summary.skipped} skipped`);
  console.log(`[${benchmarkName}] 📁 POC logs saved to: ${logsDir}`);

  return { total: pocFiles.length, passed, failed, results };
}

interface CLIOptions {
  repoPath: string;
  benchmarks?: string[];
  model?: AIModel;
  anthropicKey?: string;
  openrouterKey?: string;
  maxParallel?: number;
  continueRun?: boolean;
  prefix?: string;
  skip?: string[];
  pace?: boolean;
  vulns?: boolean;
}

/**
 * Get list of benchmarks that have already been run by checking ~/.pensar/executions
 * A benchmark is considered "complete" only if its directory contains benchmark_results.json
 * @param prefix Optional prefix to filter by (matches {prefix}-XBEN-* or {prefix}-FullChain* pattern)
 * @param isPace If true, match PACEbench FullChain patterns instead of XBEN
 */
function getCompletedBenchmarks(prefix?: string, isPace?: boolean): string[] {
  const executionsDir = path.join(process.env.HOME || "", ".pensar", "executions");

  if (!existsSync(executionsDir)) {
    return [];
  }

  try {
    const entries = readdirSync(executionsDir);
    const completedBenchmarks = new Set<string>();

    // Build the pattern based on prefix and benchmark type
    const patternPrefix = prefix || "benchmark";

    // Patterns for XBEN benchmarks
    const xbenNewPattern = new RegExp(`^${patternPrefix}-(XBEN-\\d+-\\d+)ses_`);
    const xbenLegacyPattern = new RegExp(`^${patternPrefix}-(XBEN-\\d+-\\d+)-[a-z0-9]+$`);

    // Patterns for PACEbench FullChain benchmarks
    const paceNewPattern = new RegExp(`^${patternPrefix}-(FullChain\\d+)ses_`);
    const paceLegacyPattern = new RegExp(`^${patternPrefix}-(FullChain\\d+)-[a-z0-9]+$`);

    for (const entry of entries) {
      const fullPath = path.join(executionsDir, entry);

      // Check if it's a directory and matches the expected pattern
      if (statSync(fullPath).isDirectory()) {
        let match;
        if (isPace) {
          match = entry.match(paceNewPattern) || entry.match(paceLegacyPattern);
        } else {
          match = entry.match(xbenNewPattern) || entry.match(xbenLegacyPattern);
        }

        if (match && match[1]) {
          // Check if benchmark_results.json exists (indicates completion)
          const resultsFile = path.join(fullPath, "benchmark_results.json");
          if (existsSync(resultsFile)) {
            completedBenchmarks.add(match[1]);
          }
        }
      }
    }

    return Array.from(completedBenchmarks);
  } catch (error: any) {
    console.warn(`Warning: Failed to read executions directory: ${error.message}`);
    return [];
  }
}

/**
 * Enumerate all XBEN-* benchmark directories in /benchmarks
 */
function enumerateXBENBenchmarks(repoPath: string): string[] {
  console.log(`🔍 Enumerating XBEN benchmarks in ${repoPath}/benchmarks...`);

  const benchmarksDir = path.join(repoPath, "benchmarks");

  if (!existsSync(benchmarksDir)) {
    throw new Error(`Benchmarks directory not found: ${benchmarksDir}`);
  }

  try {
    const entries = readdirSync(benchmarksDir);

    const xbenBenchmarks = entries.filter((entry) => {
      const fullPath = path.join(benchmarksDir, entry);
      const isDirectory = statSync(fullPath).isDirectory();
      const isXBEN = entry.startsWith("XBEN");
      return isDirectory && isXBEN;
    });

    console.log(`✅ Found ${xbenBenchmarks.length} XBEN benchmarks: ${xbenBenchmarks.join(", ")}`);

    return xbenBenchmarks;
  } catch (error: any) {
    throw new Error(`Failed to enumerate benchmarks: ${error.message}`);
  }
}

/**
 * Enumerate all FullChain* benchmark directories in /docker/FullChain
 */
function enumeratePACEBenchmarks(repoPath: string): string[] {
  console.log(`🔍 Enumerating PACEbench FullChain challenges in ${repoPath}/docker/FullChain...`);

  const fullchainDir = path.join(repoPath, "docker", "FullChain");

  if (!existsSync(fullchainDir)) {
    throw new Error(`FullChain directory not found: ${fullchainDir}`);
  }

  try {
    const entries = readdirSync(fullchainDir);

    const fullchainBenchmarks = entries.filter((entry) => {
      const fullPath = path.join(fullchainDir, entry);
      const isDirectory = statSync(fullPath).isDirectory();
      const isFullChain = entry.startsWith("FullChain");
      return isDirectory && isFullChain;
    });

    console.log(`✅ Found ${fullchainBenchmarks.length} FullChain challenges: ${fullchainBenchmarks.join(", ")}`);

    return fullchainBenchmarks;
  } catch (error: any) {
    throw new Error(`Failed to enumerate PACEbench challenges: ${error.message}`);
  }
}

/**
 * Get the benchmark path based on benchmark type
 */
function getBenchmarkPath(repoPath: string, benchmarkName: string, isPace: boolean): string {
  if (isPace) {
    return path.join(repoPath, "docker", "FullChain", benchmarkName);
  }
  return path.join(repoPath, "benchmarks", benchmarkName);
}

/**
 * Run a single benchmark locally
 */
async function runSingleBenchmark(
  benchmarkPath: string,
  benchmarkName: string,
  model: AIModel,
  prefix?: string,
  isPace?: boolean,
  vulnsMode?: boolean
): Promise<BenchmarkResults> {
  const startTime = Date.now();

  try {
    console.log(`\n${"=".repeat(80)}`);
    console.log(`[${benchmarkName}] STARTING LOCAL BENCHMARK`);
    console.log(`${"=".repeat(80)}`);
    console.log(`[${benchmarkName}] Path: ${benchmarkPath}`);
    console.log(`[${benchmarkName}] Model: ${model}`);
    console.log(`[${benchmarkName}] Type: ${isPace ? "PACEbench" : "XBEN"}${vulnsMode ? " (vulnerability mode)" : ""}`);
    console.log(`${"=".repeat(80)}\n`);

    // Step 1: Parse docker-compose port before building and ensure ports are forwarded
    console.log(`[${benchmarkName}] 🔍 Parsing docker-compose for web service...`);
    const portInfo = parseDockerComposePort(benchmarkPath);
    console.log(`[${benchmarkName}] ✅ Found web service: ${portInfo.serviceName} on port ${portInfo.hostPort}${portInfo.needsPortMapping ? " (added port mapping)" : ""}`);

    // Step 2: Extract flag(s) from local benchmark directory
    // For PACEbench, extract multiple flags; for XBEN, extract single flag
    console.log(`[${benchmarkName}] 🔍 Extracting flag(s) from benchmark...`);

    let expectedFlag: string | null = null;
    let expectedFlags: Array<{ name: string; value: string }> = [];

    if (isPace) {
      // PACEbench: Extract multiple flags from flags/ directory
      expectedFlags = await extractPACEFlags(benchmarkPath, benchmarkName);
      if (expectedFlags.length > 0) {
        console.log(`[${benchmarkName}] ✅ Found ${expectedFlags.length} PACE flags`);
        // Use the first flag for docker build (if needed)
        expectedFlag = expectedFlags[0]?.value || null;
      } else {
        console.log(`[${benchmarkName}] ⚠️  No PACE flags found in benchmark`);
      }
    } else {
      // XBEN: Extract single flag computed from benchmark name
      expectedFlag = await extractFlagFromRepo(benchmarkPath, benchmarkName);
      if (expectedFlag) {
        console.log(`[${benchmarkName}] ✅ FLAG found: ${expectedFlag.substring(0, 20)}...`);
      } else {
        console.log(`[${benchmarkName}] ⚠️  FLAG not found in benchmark`);
      }
    }

    // Step 3: Build docker images with flag injection using make build
    console.log(`[${benchmarkName}] 🔨 Building docker images with make build...`);

    // Change to benchmark directory and run make build
    const buildResult = await exec("make build", {
      cwd: benchmarkPath,
      env: {
        ...process.env,
        // Pass the flag as environment variable if needed
        FLAG: expectedFlag || "",
      },
    });

    console.log(`[${benchmarkName}] ✅ Docker images built`);
    if (buildResult.stdout) {
      console.log(`[${benchmarkName}] Build output: ${buildResult.stdout.substring(0, 200)}...`);
    }

    // Step 4: Start docker compose
    console.log(`[${benchmarkName}] 🐳 Starting docker compose...`);
    await exec("docker compose up -d --wait", { cwd: benchmarkPath });
    console.log(`[${benchmarkName}] ✅ Docker compose started`);

    // Wait a bit for services to be ready
    console.log(`[${benchmarkName}] ⏳ Waiting for services to be ready...`);
    await new Promise((resolve) => setTimeout(resolve, 10000));

    // Step 5: Query Docker to get the actual mapped host port
    console.log(`[${benchmarkName}] 🔍 Querying Docker for actual port mapping...`);
    const actualHostPort = await getActualDockerPort(
      benchmarkPath,
      portInfo.serviceName,
      portInfo.containerPort
    );

    // Step 6: Build target URL from actual mapped port
    const targetUrl = `http://localhost:${actualHostPort}`;
    console.log(`[${benchmarkName}] 🎯 Target URL: ${targetUrl}`);

    // Step 7: Create local session with benchmark guidance and scope constraints
    const sessionPrefix = prefix ? `${prefix}-${benchmarkName}` : `benchmark-${benchmarkName}`;
    const session = await Session.create({
      targets: [targetUrl],
      name: `Benchmark testing for ${benchmarkName}`,
      prefix: sessionPrefix,
      config: {
        outcomeGuidance: Session.BENCHMARK_OUTCOME_GUIDANCE,
        scopeConstraints: {
          allowedHosts: ['localhost'],
          allowedPorts: [actualHostPort],
          strictScope: true,
        },
      },
    });

    console.log(`[${benchmarkName}] 📝 Local session created: ${session.id}`);

    // Step 8: Create tool overrides that block docker commands and filesystem access
    // These prevent cheating by accessing Docker containers directly or reading source code
    const BLOCKED_DOCKER_COMMANDS = [
      "docker",
      "docker-compose",
      "dockerd",
      "containerd",
      "ctr",
      "nerdctl",
    ];

    // Blocked filesystem paths - prevent reading benchmark source code or container data
    const BLOCKED_FS_PATHS = [
      benchmarkPath, // Prevent access to benchmark source code
      "/var/lib/docker", // Prevent direct access to container filesystems/databases
    ];

    const executeCommandOverride = async (
      opts: ExecuteCommandOpts
    ): Promise<ExecuteCommandResult> => {
      try {
        // Check for blocked docker commands
        const commandLower = opts.command.toLowerCase().trim();
        const firstWord = commandLower.split(/\s+/)[0] || "";

        // Block docker commands to prevent cheating
        if (
          BLOCKED_DOCKER_COMMANDS.some(
            (blocked) =>
              firstWord === blocked ||
              firstWord.startsWith(`${blocked} `) ||
              commandLower.includes("docker ") ||
              commandLower.includes("docker-compose ")
          )
        ) {
          return {
            command: opts.command,
            success: false,
            stdout: "",
            stderr:
              "Docker commands are blocked in benchmark mode to prevent cheating. Use HTTP requests to interact with the target application.",
            error: "Docker commands are blocked in benchmark mode",
          };
        }

        // Block filesystem access to benchmark source code directory
        // This prevents cheating by reading source code directly
        for (const blockedPath of BLOCKED_FS_PATHS) {
          if (opts.command.includes(blockedPath)) {
            return {
              command: opts.command,
              success: false,
              stdout: "",
              stderr: `Access to ${blockedPath} is blocked in benchmark mode to prevent cheating. Use HTTP requests to interact with the target application.`,
              error: `Filesystem access to ${blockedPath} is blocked in benchmark mode`,
            };
          }
        }

        // Execute command locally with timeout
        const effectiveTimeout = opts.timeout || 120000;
        const { stdout, stderr } = await exec(opts.command, {
          timeout: effectiveTimeout,
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        });

        return {
          command: opts.command,
          success: true,
          stdout,
          stderr,
          error: "",
        };
      } catch (error: any) {
        return {
          command: opts.command,
          success: false,
          stdout: error.stdout || "",
          stderr: error.stderr || error.message || String(error),
          error: error.message || String(error),
        };
      }
    };

    // Step 9: Run streamlined pentest with tool overrides (scope constraints are in session config)
    console.log(`[${benchmarkName}] 🔍 Starting streamlined pentest...`);
    console.log(`[${benchmarkName}] ℹ️  Tool overrides active: Docker commands and source code access BLOCKED`);
    const pentestResult = await runStreamlinedPentest({
      target: targetUrl,
      model,
      session,
      toolOverride: {
        execute_command: executeCommandOverride,
      },
      onProgress: (status) => {
        const progressParts: string[] = [`[${benchmarkName}] [${status.phase}]`];

        if (status.tasksCompleted !== undefined && status.totalTasks !== undefined) {
          progressParts.push(`[${status.tasksCompleted}/${status.totalTasks} tasks]`);
        }
        if (status.activeAgents !== undefined && status.activeAgents > 0) {
          progressParts.push(`[${status.activeAgents} active]`);
        }
        progressParts.push(status.message);

        console.log(progressParts.join(' '));

        if (status.findingsCount !== undefined && status.findingsCount > 0) {
          console.log(`[${benchmarkName}]   Findings so far: ${status.findingsCount}`);
        }
      },
    });

    if (!pentestResult.success) {
      console.log(`[${benchmarkName}] ⚠️  Pentest completed with error: ${pentestResult.error}`);
    }

    console.log(`[${benchmarkName}] ✅ Pentest completed. Total findings: ${pentestResult.totalFindings}`);

    // Step 10: Detect flag in artifacts
    console.log(`[${benchmarkName}] 🎯 Detecting flag in artifacts...`);
    let flagDetection;
    if (isPace && expectedFlags.length > 0) {
      // PACEbench: Detect multiple flags
      flagDetection = await detectMultipleFlagsInArtifacts(
        session.rootPath,
        expectedFlags,
        benchmarkName
      );
    } else if (expectedFlag) {
      // XBEN: Detect single flag
      flagDetection = await detectFlagInArtifacts(
        session.rootPath,
        expectedFlag,
        benchmarkName
      );
    } else {
      flagDetection = {
        detected: false,
        flagValue: null,
        foundIn: [],
        locations: [],
        searchLocations: [],
      };
    }

    // Step 11: Re-run all POCs and save their outputs
    console.log(`[${benchmarkName}] 🔄 Re-running POCs...`);
    const pocRunResults = await rerunAllPocs(session.rootPath, benchmarkName, targetUrl);

    // Step 12: Generate benchmark results
    const results: BenchmarkResults = {
      repoPath: benchmarkPath,
      branch: benchmarkName,
      targetUrl,
      sessionId: session.id,
      sessionPath: session.rootPath,
      flagDetection,
      expectedFlag,
      pocRunSummary: pocRunResults.total > 0 ? {
        total: pocRunResults.total,
        passed: pocRunResults.passed,
        failed: pocRunResults.failed,
        skipped: pocRunResults.results.filter(r => r.exitCode === null).length,
        results: pocRunResults.results.map(r => ({
          pocFile: r.pocFile,
          pocName: r.pocName,
          exitCode: r.exitCode,
          success: r.success,
          duration: r.duration,
          error: r.error,
        })),
      } : undefined,
      timestamp: new Date().toISOString(),
    };

    const reportPath = path.join(session.rootPath, "benchmark_results.json");
    writeFileSync(reportPath, JSON.stringify(results, null, 2));

    console.log(`\n[${benchmarkName}] 📄 Benchmark report saved to: ${reportPath}`);
    console.log(`\n[${benchmarkName}] 🎯 FLAG STATUS: ${flagDetection.detected ? "✅ DETECTED" : "❌ NOT DETECTED"}`);
    if (flagDetection.detected) {
      console.log(`[${benchmarkName}]    Found in: ${flagDetection.foundIn.join(", ")}`);
      if (flagDetection.locations && flagDetection.locations.length > 0) {
        console.log(`[${benchmarkName}]    Exact locations:`);
        for (const loc of flagDetection.locations.slice(0, 5)) { // Show first 5 locations
          console.log(`[${benchmarkName}]      ${loc.file}:${loc.line}`);
        }
        if (flagDetection.locations.length > 5) {
          console.log(`[${benchmarkName}]      ... and ${flagDetection.locations.length - 5} more`);
        }
      }
    }
    if (pocRunResults.total > 0) {
      console.log(`\n[${benchmarkName}] 🧪 POC RESULTS: ${pocRunResults.passed}/${pocRunResults.total} passed`);
    }

    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.log(`\n[${benchmarkName}] ✅ Completed in ${duration}m`);

    return results;
  } catch (error: any) {
    const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
    console.error(`\n[${benchmarkName}] ❌ Failed after ${duration}m: ${error.message}`);

    // Return a failure result
    return {
      repoPath: benchmarkPath,
      branch: benchmarkName,
      targetUrl: "",
      sessionId: "",
      sessionPath: "",
      flagDetection: {
        detected: false,
        flagValue: null,
        foundIn: [],
        locations: [],
        searchLocations: [],
      },
      expectedFlag: null,
      timestamp: new Date().toISOString(),
    };
  } finally {
    // Step 13: Cleanup - Stop docker compose
    try {
      console.log(`[${benchmarkName}] 🧹 Stopping docker compose...`);
      await exec("docker compose down", { cwd: benchmarkPath });
      console.log(`[${benchmarkName}] ✅ Cleanup complete`);
    } catch (cleanupError: any) {
      console.error(`[${benchmarkName}] ⚠️  Cleanup failed: ${cleanupError.message}`);
    }
  }
}

/**
 * Run multiple benchmarks in parallel
 */
async function runMultipleBenchmarks(
  repoPath: string,
  benchmarks: string[],
  model: AIModel,
  maxParallel: number,
  prefix?: string,
  isPace?: boolean,
  vulnsMode?: boolean
): Promise<BenchmarkResults[]> {
  const startTime = Date.now();

  console.log("\n" + "=".repeat(80));
  console.log("🚀 STARTING PARALLEL LOCAL BENCHMARK EXECUTION");
  console.log("=".repeat(80));
  console.log(`Repository: ${repoPath}`);
  console.log(`Benchmark Type: ${isPace ? "PACEbench FullChain" : "XBEN"}${vulnsMode ? " (vulnerability detection mode)" : ""}`);
  console.log(`Benchmarks: ${benchmarks.length}`);
  console.log(`Model: ${model}`);
  console.log(`Max Parallel: ${maxParallel}`);
  console.log("=".repeat(80) + "\n");

  // Run with concurrency limit
  const limit = pLimit(maxParallel);
  const results = await Promise.all(
    benchmarks.map((benchmarkName) =>
      limit(() => {
        const benchmarkPath = getBenchmarkPath(repoPath, benchmarkName, !!isPace);
        return runSingleBenchmark(benchmarkPath, benchmarkName, model, prefix, isPace, vulnsMode);
      })
    )
  );

  const totalDuration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
  const flagsDetected = results.filter((r) => r.flagDetection?.detected).length;
  const flagsMissed = results.filter((r) => !r.flagDetection?.detected).length;

  // Aggregate POC results
  const totalPocs = results.reduce((sum, r) => sum + (r.pocRunSummary?.total || 0), 0);
  const passedPocs = results.reduce((sum, r) => sum + (r.pocRunSummary?.passed || 0), 0);
  const failedPocs = results.reduce((sum, r) => sum + (r.pocRunSummary?.failed || 0), 0);

  console.log("\n" + "=".repeat(80));
  console.log("📊 BENCHMARK SUMMARY");
  console.log("=".repeat(80));
  console.log(`Total Duration: ${totalDuration}m`);
  console.log(`Total Benchmarks: ${benchmarks.length}`);
  console.log(`Flags Detected: ${flagsDetected}/${benchmarks.length} (${Math.round((flagsDetected / benchmarks.length) * 100)}%)`);
  console.log(`Flags Missed: ${flagsMissed}/${benchmarks.length}`);
  if (totalPocs > 0) {
    console.log(`POCs Passed: ${passedPocs}/${totalPocs} (${Math.round((passedPocs / totalPocs) * 100)}%)`);
  }
  console.log("=".repeat(80));

  // Generate summary report
  const summaryDirName = prefix
    ? `${prefix}-${new Date().toISOString().replace(/[:.]/g, "-")}`
    : `local-run-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  const summaryDir = path.join(
    process.cwd(),
    ".pensar",
    "benchmarks",
    "executions",
    summaryDirName
  );

  mkdirSync(summaryDir, { recursive: true });

  const summary = {
    timestamp: new Date().toISOString(),
    repoPath,
    model,
    mode: "local",
    totalBenchmarks: benchmarks.length,
    flagsDetected,
    flagsMissed,
    pocStats: {
      total: totalPocs,
      passed: passedPocs,
      failed: failedPocs,
    },
    duration: totalDuration,
    benchmarks: results.map((r) => ({
      benchmark: r.branch,
      flagDetected: r.flagDetection?.detected || false,
      expectedFlag: r.expectedFlag,
      foundIn: r.flagDetection?.foundIn || [],
      sessionPath: r.sessionPath,
      pocResults: r.pocRunSummary ? {
        total: r.pocRunSummary.total,
        passed: r.pocRunSummary.passed,
        failed: r.pocRunSummary.failed,
      } : undefined,
    })),
  };

  writeFileSync(
    path.join(summaryDir, "summary.json"),
    JSON.stringify(summary, null, 2)
  );

  // Generate markdown summary
  const markdown = generateMarkdownSummary(summary);
  writeFileSync(path.join(summaryDir, "summary.md"), markdown);

  console.log(`\n📄 Summary report saved to: ${summaryDir}/summary.json`);
  console.log(`📄 Markdown report saved to: ${summaryDir}/summary.md\n`);

  return results;
}

/**
 * Generate markdown summary report
 */
function generateMarkdownSummary(summary: any): string {
  const lines = [
    "# Local Benchmark Results",
    "",
    `**Repository**: ${summary.repoPath}`,
    `**Model**: ${summary.model}`,
    `**Mode**: Local Execution`,
    `**Timestamp**: ${new Date(summary.timestamp).toLocaleString()}`,
    `**Duration**: ${summary.duration}m`,
    "",
    "## Summary",
    "",
    `- Total Benchmarks: ${summary.totalBenchmarks}`,
    `- Successful: ${summary.successful}/${summary.totalBenchmarks}`,
    `- Failed: ${summary.failed}/${summary.totalBenchmarks}`,
    `- Flags Detected: ${summary.flagsDetected}/${summary.totalBenchmarks} (${Math.round((summary.flagsDetected / summary.totalBenchmarks) * 100)}%)`,
    `- Flags Missed: ${summary.flagsMissed}/${summary.totalBenchmarks}`,
  ];

  // Add POC stats if available
  if (summary.pocStats && summary.pocStats.total > 0) {
    lines.push(`- POCs Passed: ${summary.pocStats.passed}/${summary.pocStats.total} (${Math.round((summary.pocStats.passed / summary.pocStats.total) * 100)}%)`);
  }

  lines.push("");
  lines.push("## Benchmark Results");
  lines.push("");

  for (const benchmark of summary.benchmarks) {
    const statusIcon = benchmark.status === "success" ? "✅" : "❌";
    const flagIcon = benchmark.flagDetected ? "🎯" : "❌";

    lines.push(`### ${statusIcon} ${benchmark.benchmark}`);
    lines.push("");
    lines.push(`- **Status**: ${benchmark.status}`);

    if (benchmark.status === "success") {
      lines.push(`- **Flag Detected**: ${flagIcon} ${benchmark.flagDetected ? "YES" : "NO"}`);
      if (benchmark.flagDetected) {
        lines.push(`  - Expected: \`${benchmark.expectedFlag}\``);
        lines.push(`  - Found in: ${benchmark.foundIn.join(", ")}`);
      }
      lines.push(`- **Metrics**:`);
      lines.push(`  - Accuracy: ${benchmark.metrics.accuracy}%`);
      lines.push(`  - Precision: ${benchmark.metrics.precision}%`);
      lines.push(`  - Recall: ${benchmark.metrics.recall}%`);
      if (benchmark.pocResults) {
        lines.push(`- **POC Results**: ${benchmark.pocResults.passed}/${benchmark.pocResults.total} passed`);
      }
      lines.push(`- **Session**: [${benchmark.sessionPath}](${benchmark.sessionPath})`);
    } else {
      lines.push(`- **Error**: ${benchmark.error}`);
    }

    lines.push("");
  }

  return lines.join("\n");
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error("Usage: bun run scripts/local-benchmark.ts <repo-path> [options] [XBEN-001-24 XBEN-002-24 ...]");
    console.error();
    console.error("Arguments:");
    console.error("  <repo-path>          Local path to benchmark challenges repository");
    console.error();
    console.error("Options:");
    console.error("  --model <model>              AI model to use (default: claude-sonnet-4-5)");
    console.error("  --anthropic-key <key>        Anthropic API key (default: ANTHROPIC_API_KEY env)");
    console.error("  --openrouter-key <key>       OpenRouter API key (default: OPENROUTER_API_KEY env)");
    console.error("  --max-parallel <num>         Max concurrent benchmarks (default: 10)");
    console.error("  --prefix <prefix>            Prefix for benchmark session names and output directories");
    console.error("  --continue                   Skip benchmarks that have already been run");
    console.error("  --skip <benchmarks>          Comma-separated list of benchmarks to skip (e.g., XBEN-001-24,XBEN-002-24)");
    console.error("  --pace                       Run PACEbench FullChain challenges instead of XBEN");
    console.error("  --vulns                      Enable vulnerability detection mode (requires --pace)");
    console.error();
    console.error("Environment Variables:");
    console.error("  ANTHROPIC_API_KEY            Anthropic API key (or --anthropic-key)");
    console.error("  OPENROUTER_API_KEY           OpenRouter API key (or --openrouter-key)");
    console.error();
    console.error("Benchmark Selection:");
    console.error("  • If no benchmarks specified: Automatically runs ALL benchmarks");
    console.error("    - XBEN mode: /benchmarks/XBEN-*");
    console.error("    - PACE mode: /docker/FullChain/FullChain*");
    console.error("  • If benchmarks specified: Runs only those specific benchmarks");
    console.error();
    console.error("Examples:");
    console.error("  # Run ALL XBEN benchmarks (auto-discovers all /benchmarks/XBEN-* directories)");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges");
    console.error();
    console.error("  # Run specific XBEN benchmark(s)");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges XBEN-001-24");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges XBEN-001-24 XBEN-002-24");
    console.error();
    console.error("  # Run ALL PACEbench FullChain challenges");
    console.error("  bun run scripts/local-benchmark.ts /path/to/pacebench --pace");
    console.error();
    console.error("  # Run specific PACEbench challenge(s)");
    console.error("  bun run scripts/local-benchmark.ts /path/to/pacebench --pace FullChain1 FullChain2");
    console.error();
    console.error("  # Run with custom model and parallel limit");
    console.error("  bun run scripts/local-benchmark.ts /path/to/xben-challenges \\");
    console.error("    --model claude-haiku-4-5 --max-parallel 2");
    console.error();
    console.error("How it works:");
    console.error("  - Runs benchmarks LOCALLY (no remote sandbox)");
    console.error("  - Starts docker compose locally for each benchmark");
    console.error("  - Runs thoroughPentestAgent locally against the running application");
    console.error("  - Docker commands and source code access are BLOCKED (anti-cheat)");
    console.error("  - Detects flags in pentest artifacts");
    console.error("  - Stops docker compose and cleans up");
    console.error("  - Generates comprehensive reports");
    console.error();
    console.error("Differences from Daytona benchmark:");
    console.error("  ✓ No Daytona API key needed");
    console.error("  ✓ Runs entirely on local machine");
    console.error("  ✓ Uses local Docker daemon");
    console.error("  ✓ Faster for local development/testing");
    console.error("  ✗ No isolation between benchmarks");
    console.error("  ✗ Limited by local machine resources");
    console.error();
    process.exit(1);
  }

  const repoPath = args[0]!;

  // Validate repo path exists
  if (!existsSync(repoPath)) {
    console.error(`Error: Repository path does not exist: ${repoPath}`);
    process.exit(1);
  }

  if (!statSync(repoPath).isDirectory()) {
    console.error(`Error: Path is not a directory: ${repoPath}`);
    process.exit(1);
  }

  // Parse options
  const options: CLIOptions = { repoPath };

  // Parse --model
  const modelIndex = args.indexOf("--model");
  if (modelIndex !== -1) {
    const modelValue = args[modelIndex + 1];
    if (!modelValue) {
      console.error("Error: --model must be followed by a model name");
      process.exit(1);
    }
    options.model = modelValue as AIModel;
  }

  // Parse --anthropic-key
  const anthropicKeyIndex = args.indexOf("--anthropic-key");
  if (anthropicKeyIndex !== -1) {
    const anthropicKeyValue = args[anthropicKeyIndex + 1];
    if (!anthropicKeyValue) {
      console.error("Error: --anthropic-key must be followed by a key");
      process.exit(1);
    }
    options.anthropicKey = anthropicKeyValue;
  }

  // Parse --openrouter-key
  const openrouterKeyIndex = args.indexOf("--openrouter-key");
  if (openrouterKeyIndex !== -1) {
    const openrouterKeyValue = args[openrouterKeyIndex + 1];
    if (!openrouterKeyValue) {
      console.error("Error: --openrouter-key must be followed by a key");
      process.exit(1);
    }
    options.openrouterKey = openrouterKeyValue;
  }

  // Parse --max-parallel
  const maxParallelIndex = args.indexOf("--max-parallel");
  if (maxParallelIndex !== -1) {
    const maxParallelValue = args[maxParallelIndex + 1];
    if (!maxParallelValue) {
      console.error("Error: --max-parallel must be followed by a number");
      process.exit(1);
    }
    const maxParallelNum = parseInt(maxParallelValue, 10);
    if (isNaN(maxParallelNum) || maxParallelNum < 1) {
      console.error("Error: --max-parallel must be a positive number");
      process.exit(1);
    }
    options.maxParallel = maxParallelNum;
  }

  // Parse --prefix
  const prefixIndex = args.indexOf("--prefix");
  if (prefixIndex !== -1) {
    const prefixValue = args[prefixIndex + 1];
    if (!prefixValue) {
      console.error("Error: --prefix must be followed by a prefix string");
      process.exit(1);
    }
    options.prefix = prefixValue;
  }

  // Parse --skip
  const skipIndex = args.indexOf("--skip");
  if (skipIndex !== -1) {
    const skipValue = args[skipIndex + 1];
    if (!skipValue) {
      console.error("Error: --skip must be followed by a comma-separated list of benchmarks");
      process.exit(1);
    }
    options.skip = skipValue.split(",").map((s) => s.trim());
  }

  // Parse --continue
  if (args.includes("--continue")) {
    options.continueRun = true;
  }

  // Parse --pace
  if (args.includes("--pace")) {
    options.pace = true;
  }

  // Parse --vulns
  if (args.includes("--vulns")) {
    options.vulns = true;
  }

  // Validate --vulns requires --pace
  if (options.vulns && !options.pace) {
    console.error("Error: --vulns flag requires --pace flag");
    process.exit(1);
  }

  // Parse benchmark arguments (anything that's not a flag or flag value)
  // Flags with values (need to skip the next arg)
  const flagsWithValues = [
    "--model",
    "--anthropic-key",
    "--openrouter-key",
    "--max-parallel",
    "--prefix",
    "--skip",
  ];

  // Boolean flags (no value, don't skip next arg)
  const booleanFlags = [
    "--continue",
    "--pace",
    "--vulns",
  ];

  const benchmarks: string[] = [];
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!;

    // Skip boolean flags (no value to skip)
    if (booleanFlags.includes(arg)) {
      continue;
    }

    // Skip flags with values and their values
    if (flagsWithValues.includes(arg)) {
      i++; // Also skip the next arg (flag value)
      continue;
    }

    // Skip if this is a value for a previous flag
    if (i > 0 && flagsWithValues.includes(args[i - 1]!)) {
      continue;
    }

    // This is a benchmark name
    benchmarks.push(arg);
  }

  // If no benchmarks specified, enumerate based on benchmark type
  let targetBenchmarks: string[];
  if (benchmarks.length === 0) {
    if (options.pace) {
      console.log("No benchmarks specified, enumerating all PACEbench FullChain challenges...\n");
      targetBenchmarks = enumeratePACEBenchmarks(repoPath);

      if (targetBenchmarks.length === 0) {
        console.error("Error: No FullChain challenges found in /docker/FullChain directory");
        console.error("Please ensure the repository has /docker/FullChain/FullChain* directories");
        console.error("Or specify benchmarks manually as arguments");
        process.exit(1);
      }
    } else {
      console.log("No benchmarks specified, enumerating all XBEN-* benchmarks...\n");
      targetBenchmarks = enumerateXBENBenchmarks(repoPath);

      if (targetBenchmarks.length === 0) {
        console.error("Error: No XBEN benchmarks found in /benchmarks directory");
        console.error("Please ensure the repository has /benchmarks/XBEN-* directories");
        console.error("Or specify benchmarks manually as arguments");
        process.exit(1);
      }
    }
  } else {
    targetBenchmarks = benchmarks;
    console.log(`Using specified benchmarks: ${targetBenchmarks.join(", ")}\n`);
  }

  // Filter out already-completed benchmarks if --continue flag is set
  if (options.continueRun) {
    const completedBenchmarks = getCompletedBenchmarks(options.prefix, options.pace);
    if (completedBenchmarks.length > 0) {
      console.log(`🔍 Found ${completedBenchmarks.length} already-completed benchmarks${options.prefix ? ` (prefix: ${options.prefix})` : ""}: ${completedBenchmarks.join(", ")}`);
      const originalCount = targetBenchmarks.length;
      targetBenchmarks = targetBenchmarks.filter(b => !completedBenchmarks.includes(b));
      const skippedCount = originalCount - targetBenchmarks.length;
      console.log(`⏭️  Skipping ${skippedCount} benchmarks, ${targetBenchmarks.length} remaining\n`);

      if (targetBenchmarks.length === 0) {
        console.log("✅ All benchmarks have already been completed!");
        process.exit(0);
      }
    } else {
      console.log(`🔍 No previously completed benchmarks found${options.prefix ? ` (prefix: ${options.prefix})` : ""}, running all benchmarks\n`);
    }
  }

  // Filter out explicitly skipped benchmarks
  if (options.skip && options.skip.length > 0) {
    const originalCount = targetBenchmarks.length;
    targetBenchmarks = targetBenchmarks.filter(b => !options.skip!.includes(b));
    const skippedCount = originalCount - targetBenchmarks.length;
    console.log(`⏭️  Skipping ${skippedCount} benchmarks via --skip flag: ${options.skip.join(", ")}`);
    console.log(`   ${targetBenchmarks.length} benchmarks remaining\n`);

    if (targetBenchmarks.length === 0) {
      console.log("❌ All benchmarks have been skipped! Nothing to run.");
      process.exit(1);
    }
  }

  options.benchmarks = targetBenchmarks;

  // Validate environment variables
  const anthropicKey = options.anthropicKey || process.env.ANTHROPIC_API_KEY;
  const openrouterKey = options.openrouterKey || process.env.OPENROUTER_API_KEY;

  if (!anthropicKey && !openrouterKey) {
    console.error("Error: At least one AI API key is required");
    console.error("Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY environment variable");
    console.error("Or use --anthropic-key or --openrouter-key flag");
    process.exit(1);
  }

  // Set environment variables for the agents to use
  if (anthropicKey) {
    process.env.ANTHROPIC_API_KEY = anthropicKey;
  }
  if (openrouterKey) {
    process.env.OPENROUTER_API_KEY = openrouterKey;
  }

  // Display configuration
  console.log("\n" + "=".repeat(80));
  console.log("LOCAL BENCHMARK RUNNER");
  console.log("=".repeat(80));
  console.log(`Repository: ${options.repoPath}`);
  console.log(`Benchmark Type: ${options.pace ? "PACEbench FullChain" : "XBEN"}${options.vulns ? " (vulnerability detection mode)" : ""}`);
  console.log(`Benchmarks: ${targetBenchmarks.join(", ")}`);
  console.log(`Total Benchmarks: ${targetBenchmarks.length}`);
  console.log(`Model: ${options.model || "claude-sonnet-4-5"}`);
  console.log(`Max Parallel: ${options.maxParallel || 10}`);
  if (options.prefix) {
    console.log(`Prefix: ${options.prefix}`);
  }
  console.log(`AI Keys: ${anthropicKey ? "Anthropic ✓" : ""} ${openrouterKey ? "OpenRouter ✓" : ""}`);
  console.log("=".repeat(80));
  console.log();
  console.log("Architecture:");
  console.log("  • Runs entirely locally (no remote sandbox)");
  console.log("  • Uses local Docker daemon");
  console.log("  • Starts docker compose for each benchmark");
  console.log("  • Runs thoroughPentestAgent locally");
  console.log("  • Docker commands and source code access BLOCKED (anti-cheat)");
  console.log("  • Detects flags in artifacts");
  console.log("  • Generates comprehensive reports");
  console.log("=".repeat(80) + "\n");

  try {
    if (targetBenchmarks.length === 1) {
      // Single benchmark - run directly
      console.log(`Running single benchmark: ${targetBenchmarks[0]}`);
      const benchmarkPath = getBenchmarkPath(repoPath, targetBenchmarks[0]!, !!options.pace);
      await runSingleBenchmark(
        benchmarkPath,
        targetBenchmarks[0]!,
        (options.model || "claude-sonnet-4-5") as AIModel,
        options.prefix,
        options.pace,
        options.vulns
      );
    } else {
      // Multiple benchmarks - run in parallel
      console.log(`Running parallel benchmark for ${targetBenchmarks.length} benchmarks`);
      await runMultipleBenchmarks(
        repoPath,
        targetBenchmarks,
        (options.model || "claude-sonnet-4-5") as AIModel,
        options.maxParallel || 10,
        options.prefix,
        options.pace,
        options.vulns
      );
    }

    console.log("\n✅ Benchmark execution completed successfully!");
  } catch (error: any) {
    console.error("\n❌ Benchmark execution failed:");
    console.error(error.message);
    if (error.stack) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});

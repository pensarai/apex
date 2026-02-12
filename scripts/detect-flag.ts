#!/usr/bin/env tsx

/**
 * Flag Detection Script
 *
 * Runs flag detection on a session directory to check if the expected flag
 * was captured during a pentest/benchmark session.
 *
 * Usage:
 *   bun run scripts/detect-flag.ts <session-directory> [--flag <expected-flag>]
 *
 * Examples:
 *   bun run scripts/detect-flag.ts ./sessions/my-session
 *   bun run scripts/detect-flag.ts ./sessions/my-session --flag "flag{abc123}"
 *   bun run scripts/detect-flag.ts ./sessions/my-session -f "flag{abc123}"
 */

import { existsSync, readFileSync } from "fs";
import path from "path";
import {
  detectFlagInArtifacts,
  extractFlagFromRepo,
  computeBenchmarkFlag,
  extractBenchmarkName,
} from "../src/core/agents/legacy/benchmark/flag-detector";

interface SessionJson {
  target?: {
    flag?: string;
    url?: string;
    repoPath?: string;
  };
  benchmark?: {
    flag?: string;
    name?: string;
  };
  config?: {
    flag?: string;
  };
}

function printUsage() {
  console.log(`
Flag Detection Script
=====================

Scans a pentest/benchmark session directory for occurrences of the expected flag.

Usage:
  bun run scripts/detect-flag.ts <session-directory> [options]

Arguments:
  session-directory    Path to the session directory to scan

Options:
  --flag, -f <value>       The expected flag to search for
                           If not provided, attempts to extract from session.json
  --repo, -r <path>        Path to the target repo (to extract flag from config files)
  --benchmark, -b <name>   XBOW benchmark name (e.g., XBEN-001-24)
                           Computes SHA256-based flag automatically
  --help, -h               Show this help message

Examples:
  # Auto-detect flag from session.json
  bun run scripts/detect-flag.ts ./sessions/benchmark-abc123

  # Specify flag explicitly
  bun run scripts/detect-flag.ts ./sessions/my-session --flag "FLAG{abc123...}"

  # Compute flag from XBOW benchmark name
  bun run scripts/detect-flag.ts ./sessions/my-session --benchmark XBEN-001-24

  # Extract flag from repo (auto-detects XBOW benchmarks)
  bun run scripts/detect-flag.ts ./sessions/my-session --repo ~/validation-benchmarks/benchmarks/XBEN-001-24
`);
}

async function main() {
  const args = process.argv.slice(2);

  // Parse arguments
  let sessionPath: string | null = null;
  let expectedFlag: string | null = null;
  let repoPath: string | null = null;
  let benchmarkName: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else if (arg === "--flag" || arg === "-f") {
      expectedFlag = args[++i];
    } else if (arg === "--repo" || arg === "-r") {
      repoPath = args[++i];
    } else if (arg === "--benchmark" || arg === "-b") {
      benchmarkName = args[++i];
    } else if (!arg.startsWith("-")) {
      sessionPath = arg;
    }
  }

  // Validate session path
  if (!sessionPath) {
    console.error("Error: Session directory is required\n");
    printUsage();
    process.exit(1);
  }

  // Resolve to absolute path
  sessionPath = path.resolve(sessionPath);

  if (!existsSync(sessionPath)) {
    console.error(`Error: Session directory not found: ${sessionPath}`);
    process.exit(1);
  }

  console.log("");
  console.log(
    "═══════════════════════════════════════════════════════════════",
  );
  console.log(
    "                    FLAG DETECTION SCANNER                      ",
  );
  console.log(
    "═══════════════════════════════════════════════════════════════",
  );
  console.log("");
  console.log(`Session: ${sessionPath}`);

  // Try to get flag from various sources (in priority order)
  if (!expectedFlag) {
    // 1. If --benchmark provided, compute SHA256-based flag
    if (benchmarkName) {
      expectedFlag = computeBenchmarkFlag(benchmarkName);
      console.log(`Benchmark: ${benchmarkName}`);
      console.log(`Flag:      ${expectedFlag} (computed from benchmark name)`);
    }

    // 2. Try session.json
    if (!expectedFlag) {
      const sessionJsonPath = path.join(sessionPath, "session.json");
      if (existsSync(sessionJsonPath)) {
        try {
          const sessionData: SessionJson = JSON.parse(
            readFileSync(sessionJsonPath, "utf-8"),
          );
          expectedFlag =
            sessionData.target?.flag ||
            sessionData.benchmark?.flag ||
            sessionData.config?.flag ||
            null;

          if (expectedFlag) {
            console.log(`Flag:    ${expectedFlag} (from session.json)`);
          }

          // Also try to detect benchmark name from session data
          if (!expectedFlag) {
            const targetUrl = sessionData.target?.url || "";
            const detectedBenchmark = extractBenchmarkName(targetUrl);
            if (detectedBenchmark) {
              expectedFlag = computeBenchmarkFlag(detectedBenchmark);
              console.log(
                `Benchmark: ${detectedBenchmark} (detected from session)`,
              );
              console.log(
                `Flag:      ${expectedFlag} (computed from benchmark name)`,
              );
            }
          }
        } catch (e) {
          console.log("Warning: Could not parse session.json");
        }
      }
    }

    // 3. Try benchmark_results.json
    if (!expectedFlag) {
      const benchmarkResultsPath = path.join(
        sessionPath,
        "benchmark_results.json",
      );
      if (existsSync(benchmarkResultsPath)) {
        try {
          const results = JSON.parse(
            readFileSync(benchmarkResultsPath, "utf-8"),
          );
          expectedFlag = results.expectedFlag || results.flag || null;

          // Also check if benchmark name is stored
          if (!expectedFlag && results.benchmarkName) {
            expectedFlag = computeBenchmarkFlag(results.benchmarkName);
            console.log(`Benchmark: ${results.benchmarkName}`);
            console.log(
              `Flag:      ${expectedFlag} (computed from benchmark_results.json)`,
            );
          } else if (expectedFlag) {
            console.log(
              `Flag:    ${expectedFlag} (from benchmark_results.json)`,
            );
          }
        } catch (e) {
          // Ignore
        }
      }
    }

    // 4. Try extracting from repo if provided
    if (!expectedFlag && repoPath) {
      repoPath = path.resolve(repoPath);
      if (existsSync(repoPath)) {
        console.log(`Repo:    ${repoPath}`);
        expectedFlag = await extractFlagFromRepo(repoPath, "detect-flag");
        if (expectedFlag) {
          console.log(`Flag:    ${expectedFlag} (extracted from repo)`);
        }
      }
    }

    // 5. Try to detect benchmark name from session directory name
    if (!expectedFlag) {
      const detectedBenchmark = extractBenchmarkName(sessionPath);
      if (detectedBenchmark) {
        expectedFlag = computeBenchmarkFlag(detectedBenchmark);
        console.log(
          `Benchmark: ${detectedBenchmark} (detected from session path)`,
        );
        console.log(
          `Flag:      ${expectedFlag} (computed from benchmark name)`,
        );
      }
    }
  } else {
    console.log(`Flag:    ${expectedFlag} (provided via --flag)`);
  }

  // Validate we have a flag
  if (!expectedFlag) {
    console.error(
      "\nError: No flag found. Please provide one using --flag or ensure session.json contains it.",
    );
    console.error(
      "       You can also use --repo to extract the flag from a repository.\n",
    );
    process.exit(1);
  }

  console.log("");
  console.log(
    "───────────────────────────────────────────────────────────────",
  );
  console.log("");

  // Run flag detection
  const result = await detectFlagInArtifacts(
    sessionPath,
    expectedFlag,
    "detect-flag",
  );

  console.log("");
  console.log(
    "───────────────────────────────────────────────────────────────",
  );
  console.log(
    "                         RESULTS                               ",
  );
  console.log(
    "───────────────────────────────────────────────────────────────",
  );
  console.log("");

  if (result.detected) {
    console.log("Status:  ✅ FLAG DETECTED");
    console.log(`Flag:    ${result.flagValue}`);
    console.log("");
    console.log("Found in files:");
    result.foundIn.forEach((file) => {
      console.log(`  - ${file}`);
    });
    console.log("");
    console.log(`Total occurrences: ${result.locations.length}`);
    console.log("");

    // Output detailed locations
    if (result.locations.length > 0) {
      console.log("Detailed locations:");
      for (const loc of result.locations.slice(0, 10)) {
        console.log(`  ${loc.file}:${loc.line}`);
        const contextPreview =
          loc.context.length > 80
            ? loc.context.substring(0, 80) + "..."
            : loc.context;
        console.log(`    └─ ${contextPreview}`);
      }
      if (result.locations.length > 10) {
        console.log(
          `  ... and ${result.locations.length - 10} more occurrences`,
        );
      }
    }
  } else {
    console.log("Status:  ❌ FLAG NOT DETECTED");
    console.log(`Flag:    ${expectedFlag}`);
    console.log("");
    console.log("Searched locations:");
    result.searchLocations.forEach((loc) => {
      console.log(`  - ${loc}`);
    });
  }

  console.log("");
  console.log(
    "═══════════════════════════════════════════════════════════════",
  );
  console.log("");

  // Output JSON result for programmatic use
  const jsonResultPath = path.join(sessionPath, "flag-detection-result.json");
  const jsonResult = {
    timestamp: new Date().toISOString(),
    sessionPath,
    expectedFlag,
    ...result,
  };

  try {
    const { writeFileSync } = await import("fs");
    writeFileSync(jsonResultPath, JSON.stringify(jsonResult, null, 2));
    console.log(`Results saved to: ${jsonResultPath}`);
  } catch (e) {
    // Non-fatal, just skip saving
  }

  // Exit with appropriate code
  process.exit(result.detected ? 0 : 1);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});

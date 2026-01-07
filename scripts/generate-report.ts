#!/usr/bin/env tsx

/**
 * Generate Report from Comparison Results
 *
 * Reads a comparison results JSON file and generates a formatted report
 * showing vulnerability detection statistics by CWE class.
 *
 * Usage:
 *   bun run scripts/generate-report.ts <json-file-path>
 *   bun run scripts/generate-report.ts /tmp/comparison-results-2026-01-05T19-08-58-654Z.json
 */

import { readFileSync } from "fs";

interface ComparisonResult {
  benchmark_id: string;
  execution_path: string;
  expected_vulnerability: string;
  expected_class: string;
  expected_file: string;
  expected_lines: string;
  difficulty: string;
  flag_detected: boolean;
  flag_value: string;
  vulnerability_found: boolean;
  vulnerability_match_score: number;
  correct_file_identified: boolean;
  correct_lines_identified: boolean;
  analysis: string;
  overall_score: number;
  findings_count: number;
  matching_finding_path: string | null;
  matching_finding_subagent: string | null;
}

interface ComparisonReport {
  summary: {
    total_benchmarks: number;
    flags_captured: number;
    vulnerabilities_found: number;
    correct_files: number;
    average_score: number;
  };
  results: ComparisonResult[];
}

interface ClassStats {
  total: number;
  found: number;
  avgScore: number;
  scores: number[];
  difficulties: Map<string, { total: number; found: number }>;
}

function generateReport(jsonPath: string): string {
  // Read and parse JSON
  const content = readFileSync(jsonPath, "utf-8");
  const report: ComparisonReport = JSON.parse(content);
  const results = report.results;

  const lines: string[] = [];
  const width = 90;

  // Build class stats
  const classStats = new Map<string, ClassStats>();

  for (const r of results) {
    const vulnClass = r.expected_class || "Unknown";
    const difficulty = r.difficulty || "unknown";

    let stats = classStats.get(vulnClass);
    if (!stats) {
      stats = {
        total: 0,
        found: 0,
        avgScore: 0,
        scores: [],
        difficulties: new Map(),
      };
      classStats.set(vulnClass, stats);
    }

    stats.total++;
    if (r.vulnerability_found) stats.found++;
    stats.scores.push(r.overall_score);

    // Track by difficulty
    let diffStats = stats.difficulties.get(difficulty);
    if (!diffStats) {
      diffStats = { total: 0, found: 0 };
      stats.difficulties.set(difficulty, diffStats);
    }
    diffStats.total++;
    if (r.vulnerability_found) diffStats.found++;
  }

  // Calculate average scores
  for (const stats of classStats.values()) {
    stats.avgScore =
      stats.scores.length > 0
        ? stats.scores.reduce((a, b) => a + b, 0) / stats.scores.length
        : 0;
  }

  // Sort by class name
  const sortedClasses = Array.from(classStats.entries()).sort((a, b) =>
    a[0].localeCompare(b[0])
  );

  // Header
  lines.push("═".repeat(width));
  lines.push(
    " ".repeat(Math.floor((width - 30) / 2)) + "BENCHMARK COMPARISON REPORT"
  );
  lines.push("═".repeat(width));
  lines.push("");

  // Summary
  const total = results.length;
  const vulnsFound = results.filter((r) => r.vulnerability_found).length;
  const avgScore =
    total > 0 ? results.reduce((sum, r) => sum + r.overall_score, 0) / total : 0;

  lines.push("SUMMARY");
  lines.push("─".repeat(50));
  lines.push(`Total Benchmarks:        ${total}`);
  lines.push(
    `Vulnerabilities Found:   ${vulnsFound}/${total} (${((100 * vulnsFound) / total).toFixed(1)}%)`
  );
  lines.push(`Average Score:           ${avgScore.toFixed(2)}`);
  lines.push("");

  // Visual bar for vuln found
  const barWidth = 50;
  const vulnFilledWidth = Math.round((vulnsFound / total) * barWidth);
  lines.push(
    `Vuln Detection: [${"█".repeat(vulnFilledWidth)}${"░".repeat(barWidth - vulnFilledWidth)}]`
  );
  lines.push("");

  // Difficulty breakdown
  const difficultyStats = new Map<string, { total: number; found: number }>();
  for (const r of results) {
    const diff = r.difficulty || "unknown";
    let stats = difficultyStats.get(diff);
    if (!stats) {
      stats = { total: 0, found: 0 };
      difficultyStats.set(diff, stats);
    }
    stats.total++;
    if (r.vulnerability_found) stats.found++;
  }

  lines.push("BY DIFFICULTY");
  lines.push("─".repeat(50));
  const diffOrder = ["easy", "medium", "hard"];
  for (const diff of diffOrder) {
    const stats = difficultyStats.get(diff);
    if (stats) {
      const rate = ((stats.found / stats.total) * 100).toFixed(0);
      const miniBar =
        "█".repeat(Math.round((stats.found / stats.total) * 10)) +
        "░".repeat(10 - Math.round((stats.found / stats.total) * 10));
      lines.push(
        `  ${diff.padEnd(10)} ${stats.found}/${stats.total}`.padEnd(25) +
          `${rate}% [${miniBar}]`
      );
    }
  }
  lines.push("");

  // Vulnerability class distribution table
  lines.push("VULNERABILITY CLASS DISTRIBUTION");
  lines.push("─".repeat(width));
  lines.push("");

  // Table header
  const classCol = 12;
  const countCol = 8;
  const foundCol = 12;
  const rateCol = 8;
  const scoreCol = 10;
  const barCol = 12;

  lines.push(
    "Class".padEnd(classCol) +
      "Count".padEnd(countCol) +
      "Found".padEnd(foundCol) +
      "Rate".padEnd(rateCol) +
      "Avg Score".padEnd(scoreCol) +
      "Detection"
  );
  lines.push("─".repeat(width));

  for (const [vulnClass, stats] of sortedClasses) {
    const rate =
      stats.total > 0 ? ((stats.found / stats.total) * 100).toFixed(0) + "%" : "0%";
    const miniBar =
      "█".repeat(Math.round((stats.found / stats.total) * 8)) +
      "░".repeat(8 - Math.round((stats.found / stats.total) * 8));

    lines.push(
      vulnClass.padEnd(classCol) +
        stats.total.toString().padEnd(countCol) +
        `${stats.found}/${stats.total}`.padEnd(foundCol) +
        rate.padEnd(rateCol) +
        stats.avgScore.toFixed(2).padEnd(scoreCol) +
        `[${miniBar}]`
    );
  }

  lines.push("");

  // Missed benchmarks section
  const missed = results.filter((r) => !r.vulnerability_found);
  if (missed.length > 0) {
    lines.push("═".repeat(width));
    lines.push("MISSED VULNERABILITIES (Not Detected)");
    lines.push("─".repeat(width));
    lines.push("");

    lines.push(
      "Benchmark".padEnd(14) +
        "Class".padEnd(12) +
        "Difficulty".padEnd(12) +
        "Vulnerability"
    );
    lines.push("─".repeat(width));

    for (const r of missed) {
      const vulnName =
        r.expected_vulnerability.length > 40
          ? r.expected_vulnerability.substring(0, 37) + "..."
          : r.expected_vulnerability;
      lines.push(
        r.benchmark_id.padEnd(14) +
          r.expected_class.padEnd(12) +
          r.difficulty.padEnd(12) +
          vulnName
      );
    }
    lines.push("");
  }

  // Top performers (100% detection rate with multiple benchmarks)
  const perfectClasses = sortedClasses.filter(
    ([_, stats]) => stats.found === stats.total && stats.total > 1
  );
  if (perfectClasses.length > 0) {
    lines.push("═".repeat(width));
    lines.push("PERFECT DETECTION CLASSES (100% with 2+ benchmarks)");
    lines.push("─".repeat(width));
    for (const [vulnClass, stats] of perfectClasses) {
      lines.push(`  ${vulnClass}: ${stats.total}/${stats.total} detected`);
    }
    lines.push("");
  }

  // Lowest performers
  const lowPerformers = sortedClasses
    .filter(([_, stats]) => stats.found / stats.total < 0.5 && stats.total >= 1)
    .sort((a, b) => a[1].found / a[1].total - b[1].found / b[1].total);

  if (lowPerformers.length > 0) {
    lines.push("═".repeat(width));
    lines.push("LOW DETECTION CLASSES (<50%)");
    lines.push("─".repeat(width));
    for (const [vulnClass, stats] of lowPerformers) {
      const rate = ((stats.found / stats.total) * 100).toFixed(0);
      lines.push(
        `  ${vulnClass}: ${stats.found}/${stats.total} (${rate}%) detected`
      );
    }
    lines.push("");
  }

  lines.push("═".repeat(width));

  return lines.join("\n");
}

function printUsage(): void {
  console.log(`
Generate Report from Comparison Results
========================================

Reads a comparison results JSON file and generates a formatted report
showing vulnerability detection statistics by CWE class.

Usage:
  bun run scripts/generate-report.ts <json-file-path>

Example:
  bun run scripts/generate-report.ts /tmp/comparison-results-2026-01-05T19-08-58-654Z.json
`);
}

// Main
const args = process.argv.slice(2);

if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
  printUsage();
  process.exit(args.length === 0 ? 1 : 0);
}

const jsonPath = args[0]!;

try {
  const report = generateReport(jsonPath);
  console.log(report);
} catch (error: any) {
  console.error(`Error: ${error.message}`);
  process.exit(1);
}

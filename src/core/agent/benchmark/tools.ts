import { tool } from "ai";
import { z } from "zod";
import { writeFileSync } from "fs";
import { join } from "path";
import type { Session } from "../sessions";
import type { AIModel } from "../../ai";
import { runAgent as runThoroughPentestAgent } from "../thoroughPentestAgent/agent";
import { startDevEnvironment, stopDevEnvironment } from "./subagents";
import { runComparisonAgent } from "./comparisonAgent";
import type { BenchmarkResults } from "./types";

/**
 * Create tools for the benchmark orchestrator agent
 */
export function createBenchmarkTools(
  session: Session,
  model: AIModel,
  abortSignal?: AbortSignal
) {
  // Tool to start development environment
  const start_dev_environment = tool({
    name: "start_dev_environment",
    description: `Start the development environment using docker compose.
    
This tool:
- Validates the repository path
- Checks out the specified branch (if provided)
- Finds and runs the docker-compose file
- Waits for services to be ready
- Returns the target URL for testing

Use this as the FIRST step in the benchmark workflow.`,
    inputSchema: z.object({
      repoPath: z.string().describe("Path to the repository"),
      branch: z.string().describe("Git branch to checkout and test"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async ({ repoPath, branch }) => {
      try {
        const devInfo = await startDevEnvironment(
          repoPath,
          branch,
          model,
          abortSignal
        );

        return {
          success: true,
          targetUrl: devInfo.targetUrl,
          composeFile: devInfo.composeFile,
          branch: devInfo.branch,
          message: `Development environment started successfully. Target URL: ${devInfo.targetUrl}`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to start development environment: ${error.message}`,
        };
      }
    },
  });

  // Tool to run thorough pentest
  const run_thorough_pentest = tool({
    name: "run_thorough_pentest",
    description: `Run the comprehensive thoroughPentestAgent on the target.
    
This tool:
- Spawns the thoroughPentestAgent orchestrator
- Runs attack surface analysis
- Spawns multiple pentest sub-agents
- Documents all findings
- Generates comprehensive reports

This is the MAIN TESTING PHASE. Wait for it to complete before proceeding.`,
    inputSchema: z.object({
      target: z
        .string()
        .describe("Target URL to test (e.g., http://localhost:3000)"),
      description: z
        .string()
        .describe("Brief description of what is being tested"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async ({ target, description }) => {
      try {
        console.log(
          `[Benchmark] Starting thorough pentest agent for target: ${target}`
        );

        // Run the thorough pentest agent with subagent callbacks
        const { streamResult, session: pentestSession } =
          runThoroughPentestAgent({
            target,
            model,
            abortSignal,
            session,
            onSubagentSpawn: (info) => {
              console.log(`\n${"┌".repeat(80)}`);
              console.log(`┃ SUBAGENT SPAWNED: ${info.name}`);
              console.log(`┃ Type: ${info.type}`);
              console.log(`┃ Target: ${info.target}`);
              console.log(`┃ ID: ${info.id}`);
              console.log(`${"└".repeat(80)}\n`);
            },
            onSubagentComplete: (subagentId, success) => {
              const status = success ? "✓ COMPLETED" : "✗ FAILED";
              console.log(`\n${"┌".repeat(80)}`);
              console.log(`┃ SUBAGENT ${status}: ${subagentId}`);
              console.log(`${"└".repeat(80)}\n`);
            },
          });

        // Consume the stream and log progress
        console.log(`\n${"=".repeat(80)}`);
        console.log(`THOROUGH PENTEST AGENT - ${target}`);
        console.log(`${"=".repeat(80)}\n`);

        for await (const delta of streamResult.fullStream) {
          if (delta.type === "text-delta") {
            process.stdout.write(delta.text);
          } else if (delta.type === "tool-call") {
            console.log(
              `\n\n[Tool] ${delta.toolName}${
                delta.input?.toolCallDescription
                  ? `: ${delta.input.toolCallDescription}`
                  : ""
              }`
            );
          } else if (delta.type === "tool-result") {
            console.log(`[Tool Complete]\n`);
          }
        }

        console.log(`\n${"=".repeat(80)}`);
        console.log(`PENTEST COMPLETE`);
        console.log(`${"=".repeat(80)}\n`);

        console.log(
          `[Benchmark] Thorough pentest completed. Session: ${pentestSession.id}`
        );

        return {
          success: true,
          sessionId: pentestSession.id,
          sessionPath: pentestSession.rootPath,
          message: `Thorough pentest completed. Session saved to ${pentestSession.rootPath}`,
        };
      } catch (error: any) {
        console.error(`[Benchmark] Pentest failed:`, error);
        return {
          success: false,
          error: error.message,
          message: `Failed to run thorough pentest: ${error.message}`,
        };
      }
    },
  });

  // Tool to compare results using comparison agent
  const compare_results = tool({
    name: "compare_results",
    description: `Compare expected findings with actual findings using an AI comparison agent.
    
This tool:
- Spawns an intelligent comparison agent
- Agent reads expected_results from the repository
- Agent reads all findings from the session's findings directory
- Agent performs semantic matching of findings
- Provides detailed comparison with matched, missed, and extra findings
- Calculates accuracy metrics: precision, recall, F1-score

The comparison agent uses AI to intelligently match findings based on semantic similarity,
not just string matching. This provides more accurate results.

Use this AFTER the pentest completes to evaluate testing accuracy.`,
    inputSchema: z.object({
      repoPath: z
        .string()
        .describe("Path to the repository with expected_results"),
      sessionPath: z
        .string()
        .describe("Path to the pentest session with findings"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async ({ repoPath, sessionPath }) => {
      try {
        console.log(
          `[Benchmark] Running comparison agent for repo: ${repoPath}, session: ${sessionPath}`
        );

        const comparison = await runComparisonAgent({
          repoPath,
          sessionPath,
          model,
          abortSignal,
        });

        const f1Score =
          comparison.precision + comparison.recall > 0
            ? (2 * comparison.precision * comparison.recall) /
              (comparison.precision + comparison.recall)
            : 0;

        return {
          success: true,
          comparison,
          metrics: {
            precision: Math.round(comparison.precision * 100),
            recall: Math.round(comparison.recall * 100),
            f1Score: Math.round(f1Score * 100),
            accuracy: Math.round(comparison.accuracy * 100),
          },
          message: `Comparison complete. Matched: ${
            comparison.matched.length
          }/${comparison.totalExpected}, Precision: ${Math.round(
            comparison.precision * 100
          )}%, Recall: ${Math.round(comparison.recall * 100)}%`,
        };
      } catch (error: any) {
        console.error(`[Benchmark] Comparison failed:`, error);
        return {
          success: false,
          error: error.message,
          message: `Failed to compare results: ${error.message}`,
        };
      }
    },
  });

  // Tool to stop development environment
  const stop_dev_environment = tool({
    name: "stop_dev_environment",
    description: `Stop and clean up the development environment.
    
This tool:
- Runs docker compose down
- Removes containers and networks
- Cleans up resources

Use this AFTER results are collected to clean up properly. Always call this even if testing failed.`,
    inputSchema: z.object({
      repoPath: z.string().describe("Path to the repository"),
      composeFile: z
        .string()
        .describe("Name of the docker-compose file (e.g., docker-compose.yml)"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async ({ repoPath, composeFile }) => {
      try {
        await stopDevEnvironment(repoPath, composeFile);

        return {
          success: true,
          message:
            "Development environment stopped and cleaned up successfully.",
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to stop environment (may need manual cleanup): ${error.message}`,
        };
      }
    },
  });

  // Tool to generate final benchmark report
  const generate_benchmark_report = tool({
    name: "generate_benchmark_report",
    description: `Generate the final benchmark report as benchmark_results.json.
    
This tool:
- Combines all benchmark data
- Creates detailed comparison report
- Includes metrics and analysis
- Saves as benchmark_results.json in the session directory

Use this as the FINAL step after all testing and comparison is complete.`,
    inputSchema: z.object({
      repoPath: z.string().describe("Repository path"),
      branch: z.string().describe("Branch that was tested"),
      targetUrl: z.string().describe("Target URL that was tested"),
      sessionPath: z.string().describe("Path to the pentest session"),
      comparison: z.any().describe("Comparison results object"),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call"),
    }),
    execute: async ({
      repoPath,
      branch,
      targetUrl,
      sessionPath,
      comparison,
    }) => {
      try {
        const results: BenchmarkResults = {
          repoPath,
          branch,
          targetUrl,
          sessionId: session.id,
          sessionPath,
          expectedResults: comparison.matched.map((m: any) => m.expected),
          actualResults: comparison.matched.map((m: any) => m.actual),
          comparison,
          timestamp: new Date().toISOString(),
        };

        const reportPath = join(session.rootPath, "benchmark_results.json");
        writeFileSync(reportPath, JSON.stringify(results, null, 2));

        return {
          success: true,
          reportPath,
          message: `Benchmark report saved to ${reportPath}`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to generate report: ${error.message}`,
        };
      }
    },
  });

  return {
    start_dev_environment,
    run_thorough_pentest,
    compare_results,
    stop_dev_environment,
    generate_benchmark_report,
  };
}

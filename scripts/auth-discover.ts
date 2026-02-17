#!/usr/bin/env tsx

/**
 * Auth Discovery CLI Script
 *
 * Standalone script to run the authentication discovery agent.
 * Analyzes an endpoint to determine if auth is required and how to approach it.
 *
 * Usage:
 *   tsx scripts/auth-discover.ts --target https://example.com/api/users
 */

import { discoverAuthentication } from "../src/core/agents/legacy/authenticationSubagent";
import { sessions } from "../src/core/session";
import type { AIModel } from "../src/core/ai";

interface AuthDiscoverOptions {
  target: string;
  model?: AIModel;
  additionalEndpoints?: string[];
  enableBrowser?: boolean;
}

async function runAuthDiscover(options: AuthDiscoverOptions): Promise<void> {
  const {
    target,
    model = "claude-sonnet-4-5" as AIModel,
    additionalEndpoints,
    enableBrowser = true,
  } = options;

  console.log("=".repeat(80));
  console.log("AUTHENTICATION DISCOVERY");
  console.log("=".repeat(80));
  console.log(`Target: ${target}`);
  console.log(`Model: ${model}`);
  console.log(`Browser Tools: ${enableBrowser ? "Enabled" : "Disabled"}`);
  if (additionalEndpoints?.length) {
    console.log(`Additional Endpoints: ${additionalEndpoints.join(", ")}`);
  }
  console.log();
  console.log("This analysis will:");
  console.log("  1. Probe the endpoint to detect authentication requirements");
  console.log("  2. Analyze response codes, headers, and content");
  console.log("  3. Identify the authentication type (form, JWT, basic, etc.)");
  console.log("  4. Reason about how to approach authentication");
  console.log("  5. Document evidence and reasoning chain");
  console.log();

  try {
    // Create session
    const session = await sessions.create({
      targets: [target],
      name: "auth-discovery",
      prefix: "auth-discover",
    });

    console.log(`Session ID: ${session.id}`);
    console.log(`Session Path: ${session.rootPath}`);
    console.log();
    console.log("=".repeat(80));
    console.log("DISCOVERY OUTPUT");
    console.log("=".repeat(80));
    console.log();

    // Run the auth discovery agent
    const result = await discoverAuthentication({
      input: {
        target,
        session,
        additionalEndpoints,
      },
      model: model as AIModel,
      enableBrowserTools: enableBrowser,
      onStepFinish: (step) => {
        // Print agent output as it happens
        if (step.text) {
          process.stdout.write(step.text);
        }
        if (step.toolCalls?.length) {
          for (const toolCall of step.toolCalls) {
            const tc = toolCall as {
              toolName: string;
              args?: Record<string, unknown>;
            };
            const desc = tc.args?.toolCallDescription;
            console.log(
              `\n[Tool Call] ${tc.toolName}${desc ? `: ${desc}` : ""}`,
            );
          }
        }
        if (step.toolResults?.length) {
          for (const toolResult of step.toolResults) {
            try {
              const resultStr = JSON.stringify(toolResult, null, 2);
              console.log(`[Tool Result]`, resultStr.slice(0, 800));
            } catch {
              console.log(`[Tool Result]`, String(toolResult));
            }
          }
        }
      },
    });

    console.log();
    console.log("=".repeat(80));
    console.log("DISCOVERY RESULTS");
    console.log("=".repeat(80));
    console.log();

    // Display structured results
    console.log(
      `Authentication Required: ${result.requiresAuth ? "YES" : "NO"}`,
    );
    console.log(`Auth Type: ${result.authType}`);
    console.log(`Confidence: ${result.confidence}%`);
    if (result.loginUrl) {
      console.log(`Login URL: ${result.loginUrl}`);
    }
    console.log();

    if (result.reasoning.length > 0) {
      console.log("Reasoning Chain:");
      result.reasoning.forEach((step, i) => {
        console.log(`  ${i + 1}. ${step}`);
      });
      console.log();
    }

    if (result.recommendedApproach) {
      console.log(`Recommended Approach: ${result.recommendedApproach}`);
      console.log();
    }

    if (result.evidence.length > 0) {
      console.log("Evidence Collected:");
      result.evidence.forEach((ev, i) => {
        console.log(`  ${i + 1}. ${ev.endpoint}`);
        if (ev.statusCode) console.log(`     Status: ${ev.statusCode}`);
        if (ev.hasLoginForm) console.log(`     Has Login Form: Yes`);
        if (ev.hasAuthHeader) console.log(`     Has Auth Header: Yes`);
        if (ev.redirectsToLogin) console.log(`     Redirects to Login: Yes`);
        if (ev.loginUrl) console.log(`     Login URL: ${ev.loginUrl}`);
        console.log(`     Notes: ${ev.notes}`);
      });
      console.log();
    }

    if (result.barriers?.length) {
      console.log("Auth Barriers Detected:");
      result.barriers.forEach((barrier, i) => {
        console.log(
          `  ${i + 1}. [${barrier.type.toUpperCase()}] ${barrier.details}`,
        );
      });
      console.log();
    }

    console.log("Summary:");
    console.log(`  ${result.summary}`);
    console.log();

    console.log("=".repeat(80));
    console.log("DISCOVERY COMPLETED");
    console.log("=".repeat(80));
    console.log(`Session Path: ${session.rootPath}`);
    console.log(`Logs: ${session.rootPath}/logs/auth-discovery.log`);
    console.log();
  } catch (error: unknown) {
    console.error("=".repeat(80));
    console.error("DISCOVERY FAILED");
    console.error("=".repeat(80));
    console.error(
      `Error: ${error instanceof Error ? error.message : String(error)}`,
    );
    if (error instanceof Error && error.stack) {
      console.error(`Stack: ${error.stack}`);
    }
    if (error instanceof Error && error.cause) {
      console.error(`Cause: ${JSON.stringify(error.cause)}`);
    }
    console.error();
    throw error;
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.error(
      "Usage: tsx scripts/auth-discover.ts --target <url> [options]",
    );
    console.error();
    console.error("Required:");
    console.error("  --target <url>           Target endpoint URL to analyze");
    console.error();
    console.error("Options:");
    console.error(
      "  --model <model>          AI model (default: claude-sonnet-4-5)",
    );
    console.error(
      "                           Options: claude-sonnet-4-5, claude-opus-4, claude-haiku-4",
    );
    console.error(
      "  --endpoint <url>         Additional endpoint to check (can be repeated)",
    );
    console.error("  --no-browser             Disable browser tools");
    console.error();
    console.error("Examples:");
    console.error("  # Basic auth discovery");
    console.error(
      "  tsx scripts/auth-discover.ts --target https://example.com/api/users",
    );
    console.error();
    console.error("  # With additional endpoints to check");
    console.error(
      "  tsx scripts/auth-discover.ts --target https://example.com/dashboard \\",
    );
    console.error(
      "    --endpoint https://example.com/login --endpoint https://example.com/api/me",
    );
    console.error();
    console.error("  # Use faster model");
    console.error(
      "  tsx scripts/auth-discover.ts --target https://api.example.com --model claude-haiku-4",
    );
    console.error();
    process.exit(args.length === 0 ? 1 : 0);
  }

  // Parse arguments
  const targetIndex = args.indexOf("--target");
  const modelIndex = args.indexOf("--model");
  const noBrowser = args.includes("--no-browser");

  if (targetIndex === -1) {
    console.error("Error: --target is required");
    process.exit(1);
  }

  const target = args[targetIndex + 1];
  if (!target) {
    console.error("Error: --target must be followed by a URL");
    process.exit(1);
  }

  let model: AIModel | undefined;
  if (modelIndex !== -1) {
    const modelArg = args[modelIndex + 1];
    if (!modelArg) {
      console.error("Error: --model must be followed by a model name");
      process.exit(1);
    }
    model = modelArg as AIModel;
  }

  // Parse additional endpoints
  const additionalEndpoints: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--endpoint") {
      const endpoint = args[i + 1];
      if (!endpoint) {
        console.error("Error: --endpoint must be followed by a URL");
        process.exit(1);
      }
      additionalEndpoints.push(endpoint);
    }
  }

  try {
    await runAuthDiscover({
      target,
      ...(model && { model }),
      ...(additionalEndpoints.length > 0 && { additionalEndpoints }),
      enableBrowser: !noBrowser,
    });
  } catch (error: unknown) {
    console.error(
      "Fatal error:",
      error instanceof Error ? error.message : String(error),
    );
    process.exit(1);
  }
}

// Run if called directly
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});

export { runAuthDiscover };

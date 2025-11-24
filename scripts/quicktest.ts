#!/usr/bin/env tsx

import { runAgent } from "../src/core/agent/pentestAgent/agent";
import type { AIModel } from "../src/core/ai";

interface QuicktestOptions {
  target: string;
  objective: string;
  model?: AIModel;
  headerMode?: 'none' | 'default' | 'custom';
  customHeaders?: Record<string, string>;
  rps?: number;
}

async function runQuicktest(options: QuicktestOptions): Promise<void> {
  const {
    target,
    objective,
    model = "claude-sonnet-4-5" as AIModel,
    headerMode = 'default',
    customHeaders,
    rps
  } = options;

  console.log("=".repeat(80));
  console.log("PENSAR QUICK PENTEST");
  console.log("=".repeat(80));
  console.log(`Target: ${target}`);
  console.log(`Objective: ${objective}`);
  console.log(`Model: ${model}`);
  console.log(`Rate Limit: ${rps ? `${rps} req/s` : 'Unlimited'}`);
  console.log(`Headers: ${headerMode === 'none' ? 'None' : headerMode === 'default' ? 'Default (pensar-apex)' : 'Custom'}`);
  if (headerMode === 'custom' && customHeaders) {
    for (const [key, value] of Object.entries(customHeaders)) {
      console.log(`  ${key}: ${value}`);
    }
  }
  console.log();

  try {
    // Build session config
    const sessionConfig = {
      offensiveHeaders: {
        mode: headerMode,
        headers: headerMode === 'custom' ? customHeaders : undefined,
      },
      ...(rps && {
        rateLimiter: {
          requestsPerSecond: rps,
        },
      }),
    };

    // Run the pentest agent
    const { streamResult, session } = runAgent({
      target,
      objective,
      model: model as AIModel,
      sessionConfig,
    });

    console.log(`Session ID: ${session.id}`);
    console.log(`Session Path: ${session.rootPath}`);
    console.log();
    console.log("=".repeat(80));
    console.log("PENTEST OUTPUT");
    console.log("=".repeat(80));
    console.log();

    // Consume the stream and display progress
    for await (const delta of streamResult.fullStream) {
      if (delta.type === "text-delta") {
        process.stdout.write(delta.text);
      } else if (delta.type === "tool-call") {
        console.log(
          `\n[Tool Call] ${delta.toolName}: ${
            delta.input.toolCallDescription || ""
          }`
        );
      } else if (delta.type === "tool-result") {
        console.log(`[Tool Result] Completed\n`);
      }
    }

    console.log();
    console.log("=".repeat(80));
    console.log("PENTEST COMPLETED");
    console.log("=".repeat(80));
    console.log(`✓ Pentest completed successfully`);
    console.log(`  Session ID: ${session.id}`);
    console.log(`  Findings: ${session.findingsPath}`);
    console.log(`  Session Path: ${session.rootPath}`);
    console.log();
  } catch (error: any) {
    console.error("=".repeat(80));
    console.error("PENTEST FAILED");
    console.error("=".repeat(80));
    console.error(`✗ Error: ${error.message}`);
    console.error();
    throw error;
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error(
      "Usage: pensar quicktest --target <target> --objective <objective> [options]"
    );
    console.error();
    console.error("Required:");
    console.error(
      "  --target <target>        Target URL or IP address to test"
    );
    console.error(
      "  --objective <objective>  Objective or goal of the pentest"
    );
    console.error();
    console.error("Options:");
    console.error(
      "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
    );
    console.error(
      "  --rps <number>           Rate limit: requests per second (default: unlimited)"
    );
    console.error(
      "  --headers <mode>         Header mode: none, default, or custom (default: default)"
    );
    console.error(
      "  --header <name:value>    Add custom header (requires --headers custom, can be repeated)"
    );
    console.error();
    console.error("Header Modes:");
    console.error(
      "  none                     No custom headers added to requests"
    );
    console.error(
      "  default                  Add 'User-Agent: pensar-apex' to all offensive requests"
    );
    console.error(
      "  custom                   Use custom headers defined with --header flag"
    );
    console.error();
    console.error("Examples:");
    console.error(
      "  pensar quicktest --target http://localhost:3000 --objective 'Find SQL injection'"
    );
    console.error(
      "  pensar quicktest --target 192.168.1.100 --objective 'Test auth bypass' --headers none"
    );
    console.error(
      "  pensar quicktest --target api.example.com --objective 'API testing' --rps 5 \\"
    );
    console.error(
      "    --headers custom --header 'User-Agent: pensar_client123' --header 'X-Bug-Bounty: researcher'"
    );
    console.error();
    process.exit(1);
  }

  // Parse arguments
  const targetIndex = args.indexOf("--target");
  const objectiveIndex = args.indexOf("--objective");
  const modelIndex = args.indexOf("--model");

  if (targetIndex === -1) {
    console.error("Error: --target is required");
    process.exit(1);
  }

  if (objectiveIndex === -1) {
    console.error("Error: --objective is required");
    process.exit(1);
  }

  const target = args[targetIndex + 1];
  const objective = args[objectiveIndex + 1];

  if (!target) {
    console.error("Error: --target must be followed by a target URL or IP");
    process.exit(1);
  }

  if (!objective) {
    console.error("Error: --objective must be followed by an objective");
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

  // Parse RPS option
  const rpsIndex = args.indexOf("--rps");
  let rps: number | undefined;
  if (rpsIndex !== -1) {
    const rpsArg = args[rpsIndex + 1];
    if (!rpsArg) {
      console.error("Error: --rps must be followed by a number");
      process.exit(1);
    }
    const parsedRps = parseInt(rpsArg, 10);
    if (isNaN(parsedRps) || parsedRps <= 0) {
      console.error("Error: --rps must be a positive number");
      process.exit(1);
    }
    rps = parsedRps;
  }

  // Parse header options
  const headersIndex = args.indexOf("--headers");
  let headerMode: 'none' | 'default' | 'custom' = 'default';
  if (headersIndex !== -1) {
    const headersArg = args[headersIndex + 1];
    if (!headersArg || !['none', 'default', 'custom'].includes(headersArg)) {
      console.error("Error: --headers must be 'none', 'default', or 'custom'");
      process.exit(1);
    }
    headerMode = headersArg as 'none' | 'default' | 'custom';
  }

  // Parse custom headers
  const customHeaders: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--header') {
      const headerArg = args[i + 1];
      if (!headerArg) {
        console.error("Error: --header must be followed by 'Name: Value'");
        process.exit(1);
      }

      // Parse "Name: Value" format
      const colonIndex = headerArg.indexOf(':');
      if (colonIndex === -1) {
        console.error("Error: --header must be in format 'Name: Value'");
        process.exit(1);
      }

      const name = headerArg.substring(0, colonIndex).trim();
      const value = headerArg.substring(colonIndex + 1).trim();

      if (!name) {
        console.error("Error: Header name cannot be empty");
        process.exit(1);
      }

      customHeaders[name] = value;
    }
  }

  // Validate custom headers usage
  if (headerMode !== 'custom' && Object.keys(customHeaders).length > 0) {
    console.error("Error: --header flag requires --headers custom");
    process.exit(1);
  }

  if (headerMode === 'custom' && Object.keys(customHeaders).length === 0) {
    console.error("Error: --headers custom requires at least one --header flag");
    process.exit(1);
  }

  try {
    await runQuicktest({
      target,
      objective,
      ...(model && { model }),
      headerMode,
      ...(headerMode === 'custom' && { customHeaders }),
      ...(rps && { rps }),
    });
  } catch (error: any) {
    console.error("Fatal error:", error.message);
    process.exit(1);
  }
}

// Run if called directly (ESM version)
// When bundled, this will be the entry point, so we always run main
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});

export { runQuicktest };

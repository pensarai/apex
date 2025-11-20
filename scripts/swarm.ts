#!/usr/bin/env tsx

import { runAgent } from "../src/core/agent/pentestAgent";
import { createSession, type Session } from "../src/core/agent/sessions";
import type { AIModel } from "../src/core/ai";
import { z } from "zod";
import { readFileSync } from "fs";
import pLimit from "p-limit";

const TargetSchema = z.array(
  z.object({
    target: z.string().describe("The target to perform a pentest on"),
    objective: z.string().describe("The objective of the pentest"),
  })
);

type Targets = z.infer<typeof TargetSchema>;

interface SwarmOptions {
  targets: Targets | string;
  model: AIModel;
  silent?: boolean;
  headerMode?: 'none' | 'default' | 'custom';
  customHeaders?: Record<string, string>;
}

export async function swarm(
  options: SwarmOptions
): Promise<Session | undefined> {
  const { targets, model, silent, headerMode = 'default', customHeaders } = options;
  let targetsArray: Targets = [];
  if (typeof targets === "string") {
    const result = TargetSchema.safeParse(JSON.parse(targets));
    if (!result.success) {
      if (!silent) {
        console.error("Invalid targets JSON");
        console.error(result.error);
      }
      return;
    }
    targetsArray = result.data;
  } else {
    targetsArray = targets;
  }

  if (!silent) {
    console.log("=".repeat(80));
    console.log("PENSAR SWARM PENTEST");
    console.log("=".repeat(80));
    console.log(`Model: ${model}`);
    console.log(`Total Targets: ${targetsArray.length}`);
    console.log();

    for (const [idx, target] of targetsArray.entries()) {
      console.log(`  [${idx + 1}] ${target.target}`);
      console.log(`      Objective: ${target.objective}`);
    }

    console.log();
    console.log("=".repeat(80));
    console.log();
  }

  if (targetsArray.length === 0) {
    if (!silent) {
      console.error("No targets provided");
    }
    return;
  }

  // Create a single session for all targets in the swarm
  const session = createSession("swarm", "Multi-target swarm pentest");

  const results: Array<{
    target: string;
    success: boolean;
    sessionId?: string;
    error?: string;
  }> = [];

  // Run pentests with concurrency limit of 5
  const limit = pLimit(5);

  const promises = targetsArray.map((target, idx) =>
    limit(async () => {
      if (!silent) {
        console.log("=".repeat(80));
        console.log(
          `[${idx + 1}/${targetsArray.length}] Starting pentest for: ${
            target.target
          }`
        );
        console.log("=".repeat(80));
        console.log();
      }

      try {
        // Build session config
        const sessionConfig = {
          offensiveHeaders: {
            mode: headerMode,
            headers: headerMode === 'custom' ? customHeaders : undefined,
          },
        };

        const { streamResult } = runAgent({
          session,
          target: target.target,
          objective: target.objective,
          model,
          silent,
          sessionConfig,
        });

        // Consume the stream and display progress
        for await (const delta of streamResult.fullStream) {
          if (delta.type === "text-delta") {
          } else if (delta.type === "tool-call") {
          } else if (delta.type === "tool-result") {
          }
        }

        if (!silent) {
          console.log();
          console.log(`✓ Pentest completed for: ${target.target}`);
          console.log();
        }

        results.push({
          target: target.target,
          success: true,
          sessionId: session.id,
        });
      } catch (error: any) {
        if (!silent) {
          console.error(`✗ Pentest failed for: ${target.target}`);
          console.error(`  Error: ${error.message}`);
          console.error();
        }

        results.push({
          target: target.target,
          success: false,
          error: error.message,
        });
      }
    })
  );

  await Promise.allSettled(promises);

  if (!silent) {
    // Print summary
    console.log("=".repeat(80));
    console.log("SWARM PENTEST SUMMARY");
    console.log("=".repeat(80));
    console.log(`Total targets: ${targetsArray.length}`);
    console.log(`Successful: ${results.filter((r) => r.success).length}`);
    console.log(`Failed: ${results.filter((r) => !r.success).length}`);
    console.log(`Session ID: ${session.id}`);
    console.log(`Session Path: ${session.rootPath}`);
    console.log();

    for (const result of results) {
      const status = result.success ? "✓" : "✗";
      console.log(`${status} ${result.target}`);
      if (result.error) {
        console.log(`  Error: ${result.error}`);
      }
    }

    console.log();
    console.log("=".repeat(80));
  }

  return session;
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error("Usage: pensar swarm <targets> [options]");
    console.error();
    console.error("Arguments:");
    console.error("  <targets>                JSON string or path to JSON file");
    console.error();
    console.error("Options:");
    console.error(
      "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
    );
    console.error("  --silent                 Suppress all output");
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
    console.error("Targets format (JSON array):");
    console.error("  [");
    console.error("    {");
    console.error('      "target": "api.example.com",');
    console.error(
      '      "objective": "Test API for injection vulnerabilities"'
    );
    console.error("    },");
    console.error("    {");
    console.error('      "target": "admin.example.com",');
    console.error('      "objective": "Test admin panel for auth bypass"');
    console.error("    }");
    console.error("  ]");
    console.error();
    console.error("Examples:");
    console.error("  pensar swarm targets.json");
    console.error("  pensar swarm targets.json --model gpt-4o");
    console.error("  pensar swarm targets.json --headers none");
    console.error(
      "  pensar swarm targets.json --headers custom --header 'User-Agent: pensar_client123'"
    );
    console.error(
      '  pensar swarm \'[{"target":"api.example.com","objective":"Test API"}]\''
    );
    process.exit(1);
  }

  const targetsInput = args[0]!;

  // Check for --model flag
  const modelIndex = args.indexOf("--model");
  let model: AIModel = "claude-sonnet-4-5";
  if (modelIndex !== -1) {
    const modelArg = args[modelIndex + 1];
    if (!modelArg) {
      console.error("Error: --model must be followed by a model name");
      process.exit(1);
    }
    model = modelArg as AIModel;
  }

  // Check for --silent flag
  const silent = args.includes("--silent");

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

  // Determine if input is a file path or JSON string
  let targetsJson: string;
  if (targetsInput.startsWith("[") || targetsInput.startsWith("{")) {
    // Input is JSON string
    targetsJson = targetsInput;
  } else {
    // Input is file path - try to read it
    try {
      targetsJson = readFileSync(targetsInput, "utf-8");
    } catch (error: any) {
      console.error(`Error reading targets file: ${error.message}`);
      process.exit(1);
    }
  }

  try {
    const session = await swarm({
      targets: targetsJson,
      model,
      silent,
      headerMode,
      ...(headerMode === 'custom' && { customHeaders }),
    });
    if (!session) {
      if (!silent) {
        console.error("No session was returned");
      }
      process.exit(1);
    }

    console.log(
      JSON.stringify(
        {
          sessionId: session.id,
          sessionPath: session.rootPath,
          target: session.target,
          objective: session.objective,
        },
        null,
        2
      )
    );
  } catch (error: any) {
    if (!silent) {
      console.error("Fatal error:", error.message);
    }
    process.exit(1);
  }
}

// Run if called directly (ESM version)
// When bundled, this will be the entry point, so we always run main
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});

export { TargetSchema };

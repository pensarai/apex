#!/usr/bin/env tsx

import { runAgent } from "../src/core/agent/attackSurfaceAgent/agent";
import { Session } from "../src/core/session";
import type { AIModel } from "../src/core/ai";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

interface AttackSurfaceOptions {
  target: string;
  objective?: string;
  model?: AIModel;
  headerMode?: 'none' | 'default' | 'custom';
  customHeaders?: Record<string, string>;
  strictScope?: boolean;
  allowedHosts?: string[];
  allowedPorts?: number[];
}

async function runAttackSurface(options: AttackSurfaceOptions): Promise<void> {
  const {
    target,
    objective = "Map the complete attack surface",
    model = "claude-sonnet-4-5" as AIModel,
    headerMode = 'default',
    customHeaders,
    strictScope = false,
    allowedHosts,
    allowedPorts
  } = options;

  console.log("=".repeat(80));
  console.log("ATTACK SURFACE ANALYSIS");
  console.log("=".repeat(80));
  console.log(`Target: ${target}`);
  console.log(`Objective: ${objective}`);
  console.log(`Model: ${model}`);
  console.log(`Headers: ${headerMode === 'none' ? 'None' : headerMode === 'default' ? 'Default (pensar-apex)' : 'Custom'}`);
  if (headerMode === 'custom' && customHeaders) {
    for (const [key, value] of Object.entries(customHeaders)) {
      console.log(`  ${key}: ${value}`);
    }
  }

  if (strictScope) {
    console.log();
    console.log("🎯 SCOPE CONSTRAINTS:");
    if (allowedHosts && allowedHosts.length > 0) {
      console.log(`  Allowed hosts: ${allowedHosts.join(', ')}`);
    }
    if (allowedPorts && allowedPorts.length > 0) {
      console.log(`  Allowed ports: ${allowedPorts.join(', ')}`);
    }
    console.log("  Mode: STRICT - Only in-scope targets will be tested");
  }

  console.log();
  console.log("This attack surface analysis will:");
  console.log("  1. Discover domains, subdomains, and infrastructure");
  console.log("  2. Enumerate web applications, APIs, and endpoints");
  console.log("  3. Map technologies and services");
  console.log("  4. Identify targets for deeper penetration testing");
  console.log("  5. Generate comprehensive asset inventory");
  console.log();

  try {
    // Build session config
    const sessionConfig = {
      offensiveHeaders: {
        mode: headerMode,
        headers: headerMode === 'custom' ? customHeaders : undefined,
      },
      ...(strictScope && {
        scopeConstraints: {
          strictScope: true,
          allowedHosts,
          allowedPorts,
        },
      }),
    };

    // Create session with config
    const session = await Session.create({
      targets: [target],
      name: objective,
      prefix: 'attack-surface',
      config: sessionConfig,
    });

    // Run the attack surface agent
    const { streamResult } = await runAgent({
      target,
      objective,
      model: model as AIModel,
      session,
    });

    console.log(`Session ID: ${session.id}`);
    console.log(`Session Path: ${session.rootPath}`);
    console.log(`Assets Directory: ${session.rootPath}/assets`);
    console.log();
    console.log("=".repeat(80));
    console.log("ANALYSIS OUTPUT");
    console.log("=".repeat(80));
    console.log();

    // Consume the stream and display progress
    for await (const delta of streamResult.fullStream) {
      if (delta.type === "text-delta") {
        process.stdout.write(delta.text);
      } else if (delta.type === "tool-call") {
        console.log(
          `\n[Tool Call] ${delta.toolName}${
            delta.input.toolCallDescription ? `: ${delta.input.toolCallDescription}` : ""
          }`
        );
      } else if (delta.type === "tool-result") {
        console.log(`[Tool Result] Completed\n`);
      }
    }

    console.log();
    console.log("=".repeat(80));
    console.log("ATTACK SURFACE ANALYSIS COMPLETED");
    console.log("=".repeat(80));
    console.log(`✓ Attack surface analysis completed successfully`);
    console.log(`  Session ID: ${session.id}`);
    console.log(`  Assets Directory: ${session.rootPath}/assets`);
    console.log(`  Results: ${session.rootPath}/attack-surface-results.json`);
    console.log(`  Session Path: ${session.rootPath}`);
    console.log();

    // Display discovered endpoints
    try {
      const resultsPath = join(session.rootPath, 'attack-surface-results.json');
      if (existsSync(resultsPath)) {
        const results = JSON.parse(readFileSync(resultsPath, 'utf-8'));

        console.log("=".repeat(80));
        console.log("DISCOVERED ENDPOINTS");
        console.log("=".repeat(80));

        if (results.discoveredAssets && results.discoveredAssets.length > 0) {
          console.log(`\nTotal Assets: ${results.summary?.totalAssets || results.discoveredAssets.length}`);
          console.log(`\nAssets:`);
          results.discoveredAssets.forEach((asset: string, index: number) => {
            console.log(`  ${index + 1}. ${asset}`);
          });
        } else {
          console.log("\nNo assets discovered");
        }

        if (results.targets && results.targets.length > 0) {
          console.log(`\n\nTargets for Deep Testing: ${results.targets.length}`);
          results.targets.forEach((target: any, index: number) => {
            console.log(`  ${index + 1}. ${target.target}`);
            console.log(`     Objective: ${target.objective}`);
          });
        }

        console.log();
      }
    } catch (error) {
      // Silently ignore if results file doesn't exist or can't be read
      console.log("\nNote: Could not read attack surface results for endpoint display");
    }
  } catch (error: any) {
    console.error("=".repeat(80));
    console.error("ATTACK SURFACE ANALYSIS FAILED");
    console.error("=".repeat(80));
    console.error(`✗ Error: ${error.message}`);
    console.error();
    throw error;
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.error(
      "Usage: tsx scripts/attack-surface.ts --target <target> [options]"
    );
    console.error();
    console.error("Required:");
    console.error(
      "  --target <target>        Target URL, domain, IP, or organization to analyze"
    );
    console.error();
    console.error("Options:");
    console.error(
      "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
    );
    console.error(
      "                           Options: claude-sonnet-4-5, claude-opus-4, claude-haiku-4"
    );
    console.error(
      "  --objective <text>       Custom objective for the analysis"
    );
    console.error(
      "  --headers <mode>         Header mode: none, default, or custom (default: default)"
    );
    console.error(
      "  --header <name:value>    Add custom header (requires --headers custom, can be repeated)"
    );
    console.error(
      "  --strict-scope           Enable strict scope constraints"
    );
    console.error(
      "  --allowed-host <host>    Allowed host for strict scope (can be repeated)"
    );
    console.error(
      "  --allowed-port <port>    Allowed port for strict scope (can be repeated)"
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
    console.error("Scope Constraints:");
    console.error(
      "  --strict-scope mode restricts testing to only specified hosts/ports."
    );
    console.error(
      "  Useful for bug bounty programs with defined scope."
    );
    console.error();
    console.error("Description:");
    console.error(
      "  This command runs an attack surface analysis that:"
    );
    console.error("  - Maps all domains, subdomains, and infrastructure");
    console.error("  - Discovers web applications, APIs, and endpoints");
    console.error("  - Identifies technologies and services");
    console.error("  - Documents all discovered assets");
    console.error("  - Identifies targets for deeper penetration testing");
    console.error();
    console.error("Examples:");
    console.error(
      "  # Basic attack surface analysis"
    );
    console.error(
      "  tsx scripts/attack-surface.ts --target example.com"
    );
    console.error();
    console.error(
      "  # Use faster model for quick reconnaissance"
    );
    console.error(
      "  tsx scripts/attack-surface.ts --target example.com --model claude-haiku-4"
    );
    console.error();
    console.error(
      "  # Strict scope for bug bounty (only test specific host)"
    );
    console.error(
      "  tsx scripts/attack-surface.ts --target https://app.example.com \\"
    );
    console.error(
      "    --strict-scope --allowed-host app.example.com --allowed-port 443"
    );
    console.error();
    console.error(
      "  # Custom headers for authenticated testing"
    );
    console.error(
      "  tsx scripts/attack-surface.ts --target api.example.com --headers custom \\"
    );
    console.error(
      "    --header 'Authorization: Bearer token123' --header 'X-API-Key: key456'"
    );
    console.error();
    process.exit(args.length === 0 ? 1 : 0);
  }

  // Parse arguments
  const targetIndex = args.indexOf("--target");
  const modelIndex = args.indexOf("--model");
  const objectiveIndex = args.indexOf("--objective");

  if (targetIndex === -1) {
    console.error("Error: --target is required");
    process.exit(1);
  }

  const target = args[targetIndex + 1];

  if (!target) {
    console.error("Error: --target must be followed by a target");
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

  let objective: string | undefined;
  if (objectiveIndex !== -1) {
    objective = args[objectiveIndex + 1];
    if (!objective) {
      console.error("Error: --objective must be followed by text");
      process.exit(1);
    }
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

  // Parse scope constraints
  const strictScope = args.includes('--strict-scope');
  const allowedHosts: string[] = [];
  const allowedPorts: number[] = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--allowed-host') {
      const host = args[i + 1];
      if (!host) {
        console.error("Error: --allowed-host must be followed by a hostname");
        process.exit(1);
      }
      allowedHosts.push(host);
    }

    if (args[i] === '--allowed-port') {
      const port = args[i + 1];
      if (!port) {
        console.error("Error: --allowed-port must be followed by a port number");
        process.exit(1);
      }
      const portNum = parseInt(port, 10);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        console.error("Error: --allowed-port must be a valid port number (1-65535)");
        process.exit(1);
      }
      allowedPorts.push(portNum);
    }
  }

  // Validate scope constraints
  if (!strictScope && (allowedHosts.length > 0 || allowedPorts.length > 0)) {
    console.error("Error: --allowed-host and --allowed-port require --strict-scope");
    process.exit(1);
  }

  try {
    await runAttackSurface({
      target,
      ...(objective && { objective }),
      ...(model && { model }),
      headerMode,
      ...(headerMode === 'custom' && { customHeaders }),
      strictScope,
      ...(allowedHosts.length > 0 && { allowedHosts }),
      ...(allowedPorts.length > 0 && { allowedPorts }),
    });
  } catch (error: any) {
    console.error("Fatal error:", error.message);
    process.exit(1);
  }
}

// Run if called directly
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});

export { runAttackSurface };

#!/usr/bin/env tsx

import { runAgent } from "../src/core/agent/pentestAgent/agent";
import type { AIModel } from "../src/core/ai";
import { traceAgent, flushBraintrust } from "../src/core/braintrust";
import { config } from "../src/core/config";

interface QuicktestOptions {
  target: string;
  objective: string;
  model?: AIModel;
}

async function runQuicktest(options: QuicktestOptions): Promise<void> {
  const { target, objective, model = "claude-sonnet-4-5" as AIModel } = options;

  console.log("=".repeat(80));
  console.log("PENSAR QUICK PENTEST");
  console.log("=".repeat(80));
  console.log(`Target: ${target}`);
  console.log(`Objective: ${objective}`);
  console.log(`Model: ${model}`);
  console.log();

  // Load config for Braintrust
  const appConfig = await config.get();
  console.log('[Braintrust Debug] Config loaded:', {
    hasAPIKey: !!appConfig.braintrustAPIKey,
    projectName: appConfig.braintrustProjectName,
    environment: appConfig.braintrustEnvironment,
  });

  try {
    console.log('[Braintrust Debug] Starting trace for pentest agent');
    // Wrap the agent execution in Braintrust trace
    await traceAgent(
      appConfig,
      'pentest',
      {
        agent_type: 'pentest',
        session_id: '', // Will be updated after runAgent
        target,
        objective,
        model: model as AIModel,
      },
      async (updateMetadata) => {
        console.log('[Braintrust Debug] Inside trace callback');

        // Run the pentest agent
        const { streamResult, session } = runAgent({
          target,
          objective,
          model: model as AIModel,
        });

        // Update metadata with session ID
        console.log('[Braintrust Debug] Updating metadata with session ID:', session.id);
        updateMetadata({ session_id: session.id });

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

        // Count findings
        let findingsCount = 0;
        try {
          const fs = await import('fs');
          if (fs.existsSync(session.findingsPath)) {
            findingsCount = fs.readdirSync(session.findingsPath).filter(f => f.endsWith('.json')).length;
          }
        } catch (err) {
          // Ignore errors counting findings
        }

        // Update final metadata
        console.log('[Braintrust Debug] Updating final metadata:', { success: true, findings_count: findingsCount });
        updateMetadata({
          success: true,
          findings_count: findingsCount,
        });

        console.log();
        console.log("=".repeat(80));
        console.log("PENTEST COMPLETED");
        console.log("=".repeat(80));
        console.log(`✓ Pentest completed successfully`);
        console.log(`  Session ID: ${session.id}`);
        console.log(`  Findings: ${session.findingsPath}`);
        console.log(`  Session Path: ${session.rootPath}`);
        console.log();

        console.log('[Braintrust Debug] Trace callback completed successfully');
      }
    ); // End of traceAgent

    // Flush Braintrust traces
    console.log('[Braintrust Debug] Flushing traces to Braintrust...');
    await flushBraintrust(appConfig);
    console.log('[Braintrust Debug] Flush completed');
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
      "Usage: pensar quicktest --target <target> --objective <objective> [--model <model>]"
    );
    console.error();
    console.error("Options:");
    console.error(
      "  --target <target>        Target URL or IP address to test (required)"
    );
    console.error(
      "  --objective <objective>  Objective or goal of the pentest (required)"
    );
    console.error(
      "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
    );
    console.error();
    console.error("Examples:");
    console.error(
      "  pensar quicktest --target http://localhost:3000 --objective 'Find SQL injection vulnerabilities'"
    );
    console.error(
      "  pensar quicktest --target 192.168.1.100 --objective 'Test for authentication bypass' --model gpt-4o"
    );
    console.error(
      "  pensar quicktest --target https://example.com --objective 'Find XSS vulnerabilities' --model claude-opus-4-1"
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

  try {
    await runQuicktest({
      target,
      objective,
      ...(model && { model }),
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

import {
  stepCountIs,
  type StreamTextResult,
  type ToolSet,
  type StreamTextOnStepFinishCallback,
  tool,
  hasToolCall,
} from "ai";
import { streamResponse, type AIModel } from "../../ai";
import { SYSTEM } from "./prompts";
import { createPentestTools } from "../tools";
import { createSession, type Session } from "../sessions";
import { z } from "zod";
import { join } from "path";
import { writeFileSync } from "fs";
import { detectOSAndEnhancePrompt } from "../utils";

export interface RunAgentProps {
  target: string;
  objective: string;
  model: AIModel;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  abortSignal?: AbortSignal;
  session?: Session;
}

export interface RunAgentResult extends StreamTextResult<ToolSet, never> {
  session: Session;
}

export function runAgent(opts: RunAgentProps): RunAgentResult {
  const { target, model, onStepFinish, abortSignal } = opts;

  // Create a new session for this attack surface analysis
  const session = opts.session || createSession(target);

  console.log(`Created attack surface session: ${session.id}`);
  console.log(`Session path: ${session.rootPath}`);

  // Create tools with session context
  const {
    analyze_scan,
    document_finding,
    execute_command,
    http_request,
    scratchpad,
  } = createPentestTools(session, model);

  // Simplified answer schema for orchestrator agent
  const create_attack_surface_report = tool({
    name: "create_attack_surface_report",
    description: `Provide attack surface analysis results to the orchestrator agent.
    
Call this at the END of your analysis with:
- Summary statistics
- Discovered assets (simple list)
- ALL targets for deep testing with objectives. Do not prioritize any targets, optimize for breadth of testing.
- Key findings`,
    inputSchema: z.object({
      summary: z
        .object({
          totalAssets: z.number(),
          totalDomains: z.number(),
          analysisComplete: z.boolean(),
        })
        .describe("Summary statistics"),

      discoveredAssets: z
        .array(z.string())
        .describe(
          "List of discovered assets with descriptions. Format: 'example.com - Web server (nginx) - Ports 80,443'"
        ),

      targets: z
        .array(
          z.object({
            target: z.string().describe("Target URL, IP, or domain"),
            objective: z.string().describe("Pentest objective for this target"),
            rationale: z
              .string()
              .describe("Why this target needs deep testing"),
          })
        )
        .describe("ALL targets for deep penetration testing"),

      keyFindings: z
        .array(z.string())
        .describe(
          "Key findings from reconnaissance. Format: '[SEVERITY] Finding description'"
        ),
    }),
    execute: async (results) => {
      // Save the results to the session for the orchestrator to access
      const resultsPath = join(session.rootPath, "attack-surface-results.json");
      writeFileSync(resultsPath, JSON.stringify(results, null, 2));

      return {
        success: true,
        resultsPath,
        summary: results.summary,
        message: `Attack surface analysis complete. ${results.summary.totalAssets} assets identified for penetration testing.`,
      };
    },
  });

  // Build the enhanced prompt with target context
  const enhancedPrompt = `
TARGET: ${target}

Session Information:
- Session ID: ${session.id}
- Findings will be saved to: ${session.findingsPath}
- Use the scratchpad tool for notes and observations

Begin your attack surface analysis by:
1. Understanding the target scope (is it a domain, IP, URL, network range, or organization?)
2. Performing comprehensive reconnaissance to map the entire attack surface
3. Identifying all assets, services, endpoints, and potential entry points
4. Categorizing discovered targets by type and risk level
5. Using the scratchpad tool to track discovered assets
6. When complete, call the create_attack_surface_report tool to generate a detailed report of the attack surface analysis

Your goal is to provide a comprehensive map of the attack surface, NOT to perform deep exploitation.
Focus on breadth of discovery rather than depth of testing.

Document all discovered assets and potential attack vectors using the document_finding tool.

You MUST provide the details final report using create_attack_surface_report tool.
`.trim();

  const systemPrompt = detectOSAndEnhancePrompt(SYSTEM);

  const streamResult = streamResponse({
    prompt: enhancedPrompt,
    system: systemPrompt,
    model,
    tools: {
      analyze_scan,
      document_finding,
      execute_command,
      http_request,
      scratchpad,
      create_attack_surface_report,
    },
    stopWhen: stepCountIs(10000),
    toolChoice: "auto", // Let the model decide when to use tools vs respond
    onStepFinish,
    abortSignal,
  });

  // Attach the session directly to the stream result object
  (streamResult as any).session = session;

  return streamResult as RunAgentResult;
}

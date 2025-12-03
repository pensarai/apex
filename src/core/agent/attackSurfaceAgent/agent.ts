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
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { detectOSAndEnhancePrompt } from "../utils";
import { mapMessages, saveSubagentMessages } from "../../messages";
import { nanoid } from "nanoid";

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

export function runAgent(opts: RunAgentProps): {
  streamResult: RunAgentResult;
  session: Session;
  subagentId: string;
} {
  const { target, model, onStepFinish, abortSignal } = opts;

  // Create a new session for this attack surface analysis
  const session = opts.session || createSession(target);

  const subagentId = `attack-surface-${nanoid(6)}`;

  console.log(`Created attack surface session: ${session.id}`);
  console.log(`Session path: ${session.rootPath}`);

  // Create assets directory for attack surface agent
  const assetsPath = join(session.rootPath, "assets");
  if (!existsSync(assetsPath)) {
    mkdirSync(assetsPath, { recursive: true });
  }

  // Create tools with session context
  const { analyze_scan, execute_command, http_request } = createPentestTools(
    session,
    model
  );

  // Attack Surface specific tool: document_asset
  const document_asset = tool({
    name: "document_asset",
    description: `Document a discovered asset during attack surface analysis.
    
Assets are inventory items discovered during reconnaissance and saved to the session's assets folder.

Use this tool to document:
- Domains and subdomains
- Web applications and APIs  
- Infrastructure services (mail, DNS, VPN, databases)
- Cloud resources (S3 buckets, CDN, cloud storage)
- Development assets (dev/staging/test environments, CI/CD, repos)

Each asset creates a JSON file in the assets directory for tracking and analysis.`,
    inputSchema: z.object({
      assetName: z
        .string()
        .describe(
          "Unique name for the asset (e.g., 'example.com', 'api.example.com', 'admin-panel')"
        ),
      assetType: z
        .enum([
          "domain",
          "subdomain",
          "web_application",
          "api",
          "admin_panel",
          "infrastructure_service",
          "cloud_resource",
          "development_asset",
          "endpoint",
        ])
        .describe("Type of asset discovered"),
      description: z
        .string()
        .describe(
          "Detailed description of the asset including what it is and why it's relevant"
        ),
      details: z
        .object({
          url: z.string().optional().describe("URL if applicable"),
          ip: z.string().optional().describe("IP address if known"),
          ports: z.array(z.number()).optional().describe("Open ports"),
          services: z
            .array(z.string())
            .optional()
            .describe("Running services (e.g., 'nginx 1.18', 'SSH 8.2')"),
          technology: z
            .array(z.string())
            .optional()
            .describe(
              "Technology stack (e.g., 'Node.js', 'Express', 'MongoDB')"
            ),
          endpoints: z
            .array(z.string())
            .optional()
            .describe("Discovered endpoints for web apps/APIs"),
          authentication: z
            .string()
            .optional()
            .describe("Authentication type if known"),
          status: z
            .string()
            .optional()
            .describe("Status (active, inactive, redirect, error)"),
        })
        .describe("Additional details about the asset"),
      riskLevel: z
        .enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        .describe("Risk level: LOW-CRITICAL (exposed/sensitive)"),
      notes: z
        .string()
        .optional()
        .describe("Additional notes or observations about the asset"),
    }),
    execute: async (asset) => {
      // Create a sanitized filename from asset name
      const sanitizedName = asset.assetName
        .toLowerCase()
        .replace(/[^a-z0-9-_.]/g, "_");
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `asset_${sanitizedName}_${timestamp}.json`;
      const filepath = join(assetsPath, filename);

      // Create asset record with metadata
      const assetRecord = {
        ...asset,
        discoveredAt: new Date().toISOString(),
        sessionId: session.id,
        target: session.target,
      };

      // Write asset to file
      writeFileSync(filepath, JSON.stringify(assetRecord, null, 2));

      return {
        success: true,
        assetName: asset.assetName,
        assetType: asset.assetType,
        riskLevel: asset.riskLevel,
        filepath,
        message: `Asset '${asset.assetName}' documented successfully in assets directory`,
      };
    },
  });

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
- Assets will be saved to: ${assetsPath}

Begin your attack surface analysis by:
1. Understanding the target scope (is it a domain, IP, URL, network range, or organization?)
2. Performing comprehensive reconnaissance to map the entire attack surface
3. Identifying all assets, services, endpoints, and potential entry points
4. Categorizing discovered targets by type and risk level
5. Document each significant asset using the document_asset tool
6. When complete, call the create_attack_surface_report tool to generate a detailed report of the attack surface analysis

Your goal is to provide a comprehensive map of the attack surface, NOT to perform deep exploitation.
Focus on breadth of discovery rather than depth of testing.

Document all discovered assets using the document_asset tool - this creates an inventory of:
- Domains and subdomains
- Web applications and APIs
- Infrastructure services
- Cloud resources
- Development environments

You MUST provide the details final report using create_attack_surface_report tool.
`.trim();

  const systemPrompt = detectOSAndEnhancePrompt(SYSTEM);

  const streamResult = streamResponse({
    prompt: enhancedPrompt,
    system: systemPrompt,
    model,
    tools: {
      analyze_scan,
      document_asset,
      execute_command,
      http_request,
      create_attack_surface_report,
    },
    stopWhen: stepCountIs(10000),
    toolChoice: "auto", // Let the model decide when to use tools vs respond
    onStepFinish,
    abortSignal,
    onFinish: ({ response }) => {
      saveSubagentMessages(session, subagentId, mapMessages(response.messages));
    },
  });

  // Attach the session directly to the stream result object
  (streamResult as any).session = session;

  return { streamResult: streamResult as RunAgentResult, session, subagentId };
}

import {
  stepCountIs,
  type StreamTextResult,
  type ToolSet,
  type StreamTextOnStepFinishCallback,
  tool,
} from "ai";
import { streamResponse, type AIModel } from "../../ai";
import { SYSTEM } from "./prompts";
import { createPentestTools } from "../tools";
import { createSession, type Session } from "../sessions";
import { z } from "zod";
import { join } from "path";
import { writeFileSync } from "fs";

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
  const { target, objective, model, onStepFinish, abortSignal } = opts;

  // Create a new session for this attack surface analysis
  const session = opts.session || createSession(target, objective);

  console.log(`Created attack surface session: ${session.id}`);
  console.log(`Session path: ${session.rootPath}`);

  // Create tools with session context
  const tools = createPentestTools(session, model);

  // Comprehensive answer schema for orchestrator agent
  const answer = tool({
    name: "answer",
    description: `Provide comprehensive attack surface analysis results to the orchestrator agent.
    
This tool should be called at the END of your attack surface analysis to return structured results
that the orchestrator can use to spawn targeted penetration testing sub-agents.

Include:
- All discovered assets organized by type and priority
- High-value targets that need deep testing
- Recommended penetration testing objectives for each target
- Summary statistics and risk assessment
- Key findings and exposures discovered during reconnaissance`,
    inputSchema: z.object({
      summary: z
        .object({
          totalAssets: z.number().describe("Total number of assets discovered"),
          totalDomains: z
            .number()
            .describe("Number of domains/subdomains found"),
          totalIPs: z.number().describe("Number of unique IP addresses"),
          totalServices: z
            .number()
            .describe("Number of services/ports discovered"),
          criticalExposures: z
            .number()
            .describe("Number of critical security exposures found"),
          highValueTargets: z
            .number()
            .describe(
              "Number of high-value targets identified for deep testing"
            ),
          analysisComplete: z
            .boolean()
            .describe("Whether the analysis is complete"),
        })
        .describe(
          "High-level summary statistics of the attack surface analysis"
        ),

      discoveredAssets: z
        .object({
          domains: z
            .array(
              z.object({
                domain: z.string().describe("Domain or subdomain name"),
                type: z
                  .enum(["main", "subdomain", "wildcard"])
                  .describe("Type of domain"),
                ipAddresses: z
                  .array(z.string())
                  .describe("Resolved IP addresses"),
                services: z
                  .array(z.string())
                  .describe("Services running (e.g., 'HTTP', 'HTTPS', 'SSH')"),
                technologies: z
                  .array(z.string())
                  .optional()
                  .describe("Detected technologies/frameworks"),
                notes: z
                  .string()
                  .optional()
                  .describe("Additional observations"),
              })
            )
            .describe("List of all discovered domains and subdomains"),

          ipAddresses: z
            .array(
              z.object({
                ip: z.string().describe("IP address"),
                openPorts: z
                  .array(z.number())
                  .describe("Open ports discovered"),
                services: z
                  .array(
                    z.object({
                      port: z.number(),
                      service: z.string(),
                      version: z.string().optional(),
                    })
                  )
                  .describe("Services running on this IP"),
                hostname: z
                  .string()
                  .optional()
                  .describe("Hostname if resolved"),
              })
            )
            .describe("List of all discovered IP addresses and their services"),

          webApplications: z
            .array(
              z.object({
                url: z.string().describe("Base URL of the web application"),
                status: z.number().describe("HTTP status code"),
                server: z.string().optional().describe("Server header value"),
                technologies: z
                  .array(z.string())
                  .describe("Detected technologies"),
                endpoints: z
                  .array(z.string())
                  .describe("Discovered endpoints/paths"),
                securityHeaders: z
                  .object({
                    hasCSP: z.boolean(),
                    hasHSTS: z.boolean(),
                    hasXFrameOptions: z.boolean(),
                  })
                  .optional()
                  .describe("Security header analysis"),
              })
            )
            .describe("List of all web applications discovered"),

          cloudResources: z
            .array(
              z.object({
                type: z
                  .enum(["s3", "azure_blob", "gcs", "cloudfront", "other"])
                  .describe("Type of cloud resource"),
                identifier: z.string().describe("Resource identifier/name"),
                url: z.string().optional().describe("Access URL if applicable"),
                accessible: z
                  .boolean()
                  .describe("Whether the resource is publicly accessible"),
                notes: z.string().optional(),
              })
            )
            .optional()
            .describe("Cloud resources discovered"),

          otherServices: z
            .array(
              z.object({
                type: z
                  .string()
                  .describe(
                    "Service type (e.g., 'Mail Server', 'FTP', 'Database')"
                  ),
                location: z.string().describe("IP:Port or hostname"),
                version: z.string().optional(),
                exposure: z.enum(["public", "restricted", "unknown"]),
                notes: z.string().optional(),
              })
            )
            .optional()
            .describe("Other services discovered (mail, ftp, databases, etc.)"),
        })
        .describe("Comprehensive inventory of all discovered assets"),

      highValueTargets: z
        .array(
          z.object({
            target: z
              .string()
              .describe("Target identifier (URL, IP, or domain)"),
            priority: z
              .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
              .describe("Priority level for penetration testing"),
            type: z
              .enum([
                "web_application",
                "api_endpoint",
                "admin_panel",
                "authentication_system",
                "database",
                "dev_environment",
                "legacy_system",
                "exposed_service",
                "cloud_resource",
                "other",
              ])
              .describe("Type of target"),
            objective: z
              .string()
              .describe(
                "Recommended penetration testing objective for this target"
              ),
            rationale: z
              .string()
              .describe("Why this target is high-value and needs deep testing"),
            discoveredVulnerabilities: z
              .array(z.string())
              .optional()
              .describe(
                "Any vulnerabilities already identified during reconnaissance"
              ),
            estimatedRisk: z
              .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
              .describe("Estimated risk level"),
            suggestedTests: z
              .array(z.string())
              .describe("Specific tests recommended for this target"),
          })
        )
        .describe(
          "High-value targets identified for deep penetration testing by sub-agents"
        ),

      keyFindings: z
        .array(
          z.object({
            title: z.string().describe("Finding title"),
            severity: z.enum([
              "CRITICAL",
              "HIGH",
              "MEDIUM",
              "LOW",
              "INFORMATIONAL",
            ]),
            category: z.enum([
              "exposed_service",
              "misconfiguration",
              "information_disclosure",
              "weak_security_posture",
              "asset_discovery",
              "technology_identification",
              "other",
            ]),
            description: z
              .string()
              .describe("Brief description of the finding"),
            affected: z
              .array(z.string())
              .describe("Affected assets (URLs, IPs, domains)"),
            impact: z.string().describe("Potential security impact"),
          })
        )
        .describe(
          "Key findings and security observations from the attack surface analysis"
        ),

      recommendations: z
        .object({
          immediateActions: z
            .array(z.string())
            .describe("Critical actions that should be taken immediately"),
          pentestingPriority: z
            .array(z.string())
            .describe(
              "Recommended order for penetration testing the high-value targets"
            ),
          assetReduction: z
            .array(z.string())
            .optional()
            .describe("Suggestions for reducing attack surface"),
          furtherInvestigation: z
            .array(z.string())
            .optional()
            .describe("Areas requiring additional investigation"),
        })
        .describe("Actionable recommendations based on the analysis"),

      metadata: z
        .object({
          sessionId: z.string().describe("Session ID for this analysis"),
          analysisStartTime: z
            .string()
            .describe("ISO timestamp when analysis started"),
          analysisEndTime: z
            .string()
            .describe("ISO timestamp when analysis completed"),
          targetScope: z.string().describe("Original target/scope provided"),
          originalObjective: z.string().describe("Original objective provided"),
          toolsUsed: z
            .array(z.string())
            .describe("List of tools/commands used during analysis"),
          reportPath: z
            .string()
            .optional()
            .describe("Path to detailed report if generated"),
        })
        .describe("Metadata about the analysis session"),
    }),
    execute: async (results) => {
      // Save the results to the session for the orchestrator to access
      const resultsPath = join(session.rootPath, "attack-surface-results.json");
      writeFileSync(resultsPath, JSON.stringify(results, null, 2));

      console.log(`Attack surface results saved to: ${resultsPath}`);
      console.log(`Total assets discovered: ${results.summary.totalAssets}`);
      console.log(
        `High-value targets for pentesting: ${results.summary.highValueTargets}`
      );

      return {
        success: true,
        resultsPath,
        summary: results.summary,
        message: `Attack surface analysis complete. ${results.summary.highValueTargets} high-value targets identified for penetration testing.`,
      };
    },
  });

  // Build the enhanced prompt with target context
  const enhancedPrompt = `
TARGET: ${target}
OBJECTIVE: ${objective}

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
6. Optionally delegating specific high-value targets to pentest_agents for deeper testing

Your goal is to provide a comprehensive map of the attack surface, NOT to perform deep exploitation.
Focus on breadth of discovery rather than depth of testing.

Document all discovered assets and potential attack vectors using the document_finding tool.
`.trim();

  const streamResult = streamResponse({
    prompt: enhancedPrompt,
    system: SYSTEM,
    model,
    tools: { ...tools, answer },
    activeTools: [
      "execute_command",
      "http_request",
      "document_finding",
      "analyze_scan",
      "scratchpad",
      "answer",
    ],
    stopWhen: stepCountIs(10000),
    toolChoice: "auto", // Let the model decide when to use tools vs respond
    onStepFinish,
    abortSignal,
  });

  // Attach the session directly to the stream result object
  (streamResult as any).session = session;

  return streamResult as RunAgentResult;
}

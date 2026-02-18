#!/usr/bin/env bun

/**
 * Pensar Apex MCP Server
 * Exposes Pensar pentesting capabilities via Model Context Protocol
 * 
 * Allows Claude/Cursor to run pentests and access security findings
 * through standardized MCP tool definitions.
 */

import {
  Server,
} from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Tool, TextContent } from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";

const server = new Server(
  {
    name: "pensar-apex-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {
        listChanged: false,
      },
    },
  },
);

/**
 * Define available tools for Claude/Cursor
 */
const tools: Tool[] = [
  {
    name: "pensar_pentest",
    description:
      "Run an autonomous penetration test against a target URL using Pensar Apex. " +
      "Returns security findings with severity levels, CVSS scores, and remediation guidance.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description:
            "The target URL to pentest (e.g., http://localhost:3000 or https://example.com)",
        },
        model: {
          type: "string",
          description:
            "AI model to use for the pentest (default: claude-haiku-4-5). Options: claude-haiku-4-5, claude-opus, claude-sonnet",
          enum: ["claude-haiku-4-5", "claude-opus", "claude-sonnet"],
        },
        output_format: {
          type: "string",
          description:
            "Format for the findings output (default: json). text for human-readable format, json for structured data",
          enum: ["json", "text"],
        },
        verbose: {
          type: "boolean",
          description: "Include detailed progress information during pentest execution",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "pensar_findings_query",
    description:
      "Query findings from a completed pentest session. Requires the session path returned by pensar_pentest.",
    inputSchema: {
      type: "object" as const,
      properties: {
        session_path: {
          type: "string",
          description: "Path to the pentest session directory",
        },
        severity_filter: {
          type: "string",
          description:
            "Filter findings by severity level (CRITICAL, HIGH, MEDIUM, LOW). Returns all if not specified.",
          enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        },
        limit: {
          type: "number",
          description: "Maximum number of findings to return (default: 50)",
        },
      },
      required: ["session_path"],
    },
  },
];

/**
 * Tool call handler
 */
server.setRequestHandler({ method: "tools/call" } as any, async (request: any) => {
  const toolName = request.params.name;
  const args = request.params.arguments || {};

  try {
    if (toolName === "pensar_pentest") {
      return await handlePentestTool(args);
    } else if (toolName === "pensar_findings_query") {
      return await handleFindingsQuery(args);
    } else {
      return {
        content: [
          {
            type: "text",
            text: `Unknown tool: ${toolName}`,
          },
        ],
        isError: true,
      };
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

/**
 * Tool list handler
 */
server.setRequestHandler({ method: "tools/list" } as any, async () => {
  return { tools };
});

/**
 * Execute pentest via CLI
 */
async function handlePentestTool(
  args: Record<string, any>,
): Promise<{ content: TextContent[]; isError?: boolean }> {
  const target = args.target as string;
  const model = (args.model || "claude-haiku-4-5") as string;
  const outputFormat = (args.output_format || "json") as "json" | "text";
  const verbose = (args.verbose || false) as boolean;

  if (!target) {
    return {
      content: [{ type: "text", text: "Error: target is required" }],
      isError: true,
    };
  }

  return new Promise((resolve) => {
    try {
      console.error(`[MCP] Starting pentest for ${target} with model ${model}`);

      const cliArgs = [
        "scripts/pentest-cli.ts",
        "--target",
        target,
        "--model",
        model,
        "--output",
        outputFormat,
      ];

      const currentCwd = process.cwd();
      const childProcess = spawn("bun", cliArgs, {
        cwd: currentCwd,
        stdio: ["pipe", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";

      const timeout = setTimeout(() => {
        childProcess.kill();
        resolve({
          content: [
            {
              type: "text",
              text: "Error: Pentest execution timed out after 30 minutes",
            },
          ],
          isError: true,
        });
      }, 30 * 60 * 1000);

      childProcess.stdout?.on("data", (data) => {
        const chunk = data.toString();
        stdout += chunk;
        if (verbose) {
          console.error(`[MCP:stdout] ${chunk}`);
        }
      });

      childProcess.stderr?.on("data", (data) => {
        const chunk = data.toString();
        stderr += chunk;
        if (verbose) {
          console.error(`[MCP:stderr] ${chunk}`);
        }
      });

      childProcess.on("close", (code) => {
        clearTimeout(timeout);

        if (code !== 0) {
          resolve({
            content: [
              {
                type: "text",
                text: `Pentest failed with exit code ${code}.\n\nOutput:\n${stdout}\n\nErrors:\n${stderr}`,
              },
            ],
            isError: true,
          });
          return;
        }

        try {
          // Try to parse JSON output
          if (outputFormat === "json") {
            const result = JSON.parse(stdout.trim());
            resolve({
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            });
          } else {
            resolve({
              content: [
                {
                  type: "text",
                  text: stdout,
                },
              ],
            });
          }
        } catch {
          resolve({
            content: [
              {
                type: "text",
                text: stdout,
              },
            ],
          });
        }
      });

      childProcess.on("error", (error) => {
        clearTimeout(timeout);
        resolve({
          content: [
            {
              type: "text",
              text: `Failed to execute pentest: ${error.message}`,
            },
          ],
          isError: true,
        });
      });
    } catch (error) {
      resolve({
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      });
    }
  });
}

/**
 * Query findings from a session
 */
async function handleFindingsQuery(
  args: Record<string, any>,
): Promise<{ content: TextContent[]; isError?: boolean }> {
  const sessionPath = args.session_path as string;
  const severityFilter = args.severity_filter as string | undefined;
  const limit = (args.limit || 50) as number;

  if (!sessionPath) {
    return {
      content: [{ type: "text", text: "Error: session_path is required" }],
      isError: true,
    };
  }

  try {
    const { loadFindings } = await import("./findings-extractor");
    const summary = loadFindings(sessionPath);

    // Filter by severity if requested
    let findings = summary.findings;
    if (severityFilter) {
      findings = findings.filter(
        (f) => f.severity === severityFilter.toUpperCase(),
      );
    }

    // Apply limit
    findings = findings.slice(0, limit);

    const result = {
      total_findings: summary.findings.length,
      filtered_findings: findings.length,
      by_severity: summary.bySeverity,
      findings: findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        description: f.description,
        impact: f.impact,
        endpoint: f.endpoint,
        remediation: f.remediation,
        cvss: f.cvss
          ? {
              score: f.cvss.score,
              severity: f.cvss.severity,
            }
          : undefined,
      })),
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: `Error querying findings: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
}

/**
 * Start the MCP server
 */
async function main() {
  console.error("[MCP Server] Starting Pensar Apex MCP Server");
  console.error("[MCP Server] Tools available:");
  tools.forEach((tool) => {
    console.error(`  - ${tool.name}: ${tool.description}`);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("[MCP Server] Server connected and ready");
}

main().catch((error) => {
  console.error("[MCP Server] Fatal error:", error);
  process.exit(1);
});

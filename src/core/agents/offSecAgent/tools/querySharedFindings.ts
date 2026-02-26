import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import type { FindingBus } from "../findingBus";

/**
 * Creates the query_shared_findings tool.
 *
 * The FindingBus instance must be passed via the tool context's `findingBus`
 * property. If no bus is available (non-swarm context), the tool returns
 * an empty result set.
 */
export function querySharedFindings(
  ctx: ToolContext & { findingBus?: FindingBus },
) {
  return tool({
    description: `Query findings discovered by other agents in the current engagement.

Use this tool to check what other pentest agents have found during this session. This is valuable for:
- Discovering credentials found by other agents that you can use for privilege escalation
- Finding endpoints or access tokens discovered by other agents
- Identifying vulnerabilities that can be chained with your findings
- Avoiding duplicate testing of already-confirmed vulnerabilities

The finding bus is shared across all agents in the current swarm.`,
    inputSchema: z.object({
      type: z
        .enum([
          "credential",
          "access",
          "vulnerability",
          "endpoint",
          "configuration",
          "information",
        ])
        .optional()
        .describe("Filter by finding type"),
      severity: z
        .enum(["critical", "high", "medium", "low"])
        .optional()
        .describe("Filter by severity"),
      relatedTo: z
        .string()
        .optional()
        .describe(
          "Filter by target URL pattern (substring match), e.g. '/api/admin'",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise description of what you're looking for (e.g., 'Checking for credentials found by other agents')",
        ),
    }),
    execute: async ({ type, severity, relatedTo }) => {
      const bus = ctx.findingBus;

      if (!bus) {
        return {
          success: true,
          count: 0,
          findings: [],
          message:
            "No shared finding bus available in this context (running in standalone mode).",
        };
      }

      const results = bus.query({ type, severity, relatedTo });

      return {
        success: true,
        count: results.length,
        findings: results.map((f) => ({
          id: f.id,
          type: f.type,
          source: f.source,
          severity: f.severity,
          target: f.target,
          data: f.data,
          timestamp: new Date(f.timestamp).toISOString(),
        })),
        message:
          results.length > 0
            ? `Found ${results.length} shared finding(s).`
            : "No matching findings from other agents yet.",
      };
    },
  });
}

import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

/**
 * Factory for the `delegate_flag_extraction` tool.
 *
 * Spawns a specialized {@link FlagExtractionAgent} that aggressively
 * attempts to extract a flag through a confirmed vulnerability. The
 * parent pentest agent provides the vulnerability details and attack
 * vector, and the extraction agent tries many approaches to retrieve
 * the flag data.
 */
export function delegateFlagExtraction(ctx: ToolContext) {
  return tool({
    description: `Delegate flag extraction to a specialized subagent.

Call this when you have confirmed a vulnerability and identified an attack vector that could lead to a flag. The extraction agent will aggressively try many approaches to extract FLAG{...} data through the vulnerability.

Provide:
- vulnerabilityDescription: what the vulnerability is (e.g. "SSRF in /api/fetch-url allows fetching internal URLs")
- attackVector: the working exploit technique (e.g. "POST to /api/fetch-url with {url: 'http://internal-api:3001/...'}")
- context: any useful info gathered so far (internal hostnames found, open ports, response patterns, endpoints discovered)

The agent will try multiple hostnames, ports, paths, and parsing techniques to find and extract the flag.`,
    inputSchema: z.object({
      vulnerabilityDescription: z
        .string()
        .describe(
          "Description of the confirmed vulnerability (e.g. 'SSRF in /api/fetch-url allows server-side requests to internal services')",
        ),
      attackVector: z
        .string()
        .describe(
          "The working attack vector with example request (e.g. 'POST http://target/api/fetch-url with JSON body {url: \"http://internal-api:3001/\"}')",
        ),
      context: z
        .string()
        .describe(
          "Any useful context: internal hostnames found, open ports, response patterns, endpoints discovered, error messages seen",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ vulnerabilityDescription, attackVector, context }) => {
      if (!ctx.model) {
        return {
          success: false,
          flag: null,
          message:
            "delegate_flag_extraction requires a model in the tool context.",
        };
      }

      const subagentId = "flag-extraction-agent";

      ctx.subagentCallbacks?.onSubagentSpawn?.({
        subagentId,
        input: { vulnerabilityDescription, attackVector },
        status: "pending",
      });

      try {
        // Dynamic import to avoid circular dependencies
        const { FlagExtractionAgent } = await import(
          "../../specialized/flagExtraction/agent"
        );

        const agent = new FlagExtractionAgent({
          target: ctx.target ?? "unknown",
          vulnerabilityDescription,
          attackVector,
          context,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          sandbox: ctx.sandbox,
        });

        const result = await agent.consume({
          subagentCallbacks: ctx.subagentCallbacks
            ? {
                onTextDelta: (d) =>
                  ctx.subagentCallbacks!.onTextDelta?.({
                    ...d,
                    subagentId,
                  }),
                onToolCall: (d) =>
                  ctx.subagentCallbacks!.onToolCall?.({
                    ...d,
                    subagentId,
                  }),
                onToolResult: (d) =>
                  ctx.subagentCallbacks!.onToolResult?.({
                    ...d,
                    subagentId,
                  }),
                onError: (e) => ctx.subagentCallbacks!.onError?.(e),
              }
            : undefined,
        });

        ctx.subagentCallbacks?.onSubagentComplete?.({
          subagentId,
          input: { vulnerabilityDescription, attackVector },
          status: "completed",
        });

        return {
          success: result.flag !== null,
          flag: result.flag,
          summary: result.summary,
          approachesTried: result.approachesTried,
          message: result.flag
            ? `Flag extracted: ${result.flag}`
            : `Flag not found after ${result.approachesTried.length} approaches. ${result.summary}`,
        };
      } catch (error) {
        ctx.subagentCallbacks?.onSubagentComplete?.({
          subagentId,
          input: { vulnerabilityDescription, attackVector },
          status: "failed",
        });

        const errorMsg =
          error instanceof Error ? error.message : String(error);
        return {
          success: false,
          flag: null,
          message: `Flag extraction agent failed: ${errorMsg}`,
        };
      }
    },
  });
}

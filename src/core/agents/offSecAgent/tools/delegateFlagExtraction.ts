import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

/**
 * Factory for the `delegate_flag_extraction` tool.
 *
 * Spawns the {@link ExploitAgent} — a recursive hypothesis-driven
 * exploit orchestrator that reasons about all session findings and
 * cross-session exploit knowledge to extract flags through confirmed
 * vulnerabilities.
 */
export function delegateFlagExtraction(ctx: ToolContext) {
  return tool({
    description: `Delegate flag extraction to a specialized exploit agent.

Call this when you have confirmed a vulnerability and identified an attack vector that could lead to a flag. The exploit agent will:
1. Analyze ALL vulnerabilities found in this session
2. Retrieve relevant exploit knowledge from past sessions
3. Generate and test exploit hypotheses in parallel
4. Iteratively refine its approach based on discoveries
5. Chain multiple vulnerabilities together when possible

Provide:
- vulnerabilityDescription: what the vulnerability is (e.g. "SSRF in /api/fetch-url allows fetching internal URLs")
- attackVector: the working exploit technique (e.g. "POST to /api/fetch-url with {url: 'http://internal-api:3001/...'}")
- context: any useful info gathered so far (internal hostnames found, open ports, response patterns, endpoints discovered)`,
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

      const subagentId = "exploit-agent";

      ctx.eventBus?.emit("subagent-spawn", {
        subagentId,
        input: { vulnerabilityDescription, attackVector },
      });

      try {
        // Dynamic imports to avoid circular dependencies
        const { ExploitAgent } = await import(
          "../../specialized/exploit/agent"
        );
        const { getKnowledgeForFindings } = await import(
          "../../../knowledge/exploitKnowledge"
        );

        // Gather all session findings for the exploit agent to reason about
        const findings = ctx.findingsRegistry?.getFindings() ?? [];

        // Load relevant exploit knowledge from past sessions
        const exploitKnowledge = await getKnowledgeForFindings(findings);

        const agent = new ExploitAgent({
          target: ctx.target ?? "unknown",
          triggeringVulnerability: {
            description: vulnerabilityDescription,
            attackVector,
            context,
          },
          findings,
          exploitKnowledge,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          sandbox: ctx.sandbox,
          eventBus: ctx.eventBus,
        });

        const result = await agent.run();

        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "completed",
        });

        return {
          success: result.flag !== null,
          flag: result.flag,
          summary: result.summary,
          approachesTried: result.approachesTried,
          roundsExecuted: result.roundsExecuted,
          totalHypothesesTested: result.totalHypothesesTested,
          message: result.flag
            ? `Flag extracted: ${result.flag} (${result.totalHypothesesTested} hypotheses across ${result.roundsExecuted} rounds)`
            : `Flag not found after ${result.totalHypothesesTested} hypotheses across ${result.roundsExecuted} rounds. ${result.summary}`,
        };
      } catch (error) {
        ctx.eventBus?.emit("subagent-complete", {
          subagentId,
          status: "failed",
        });

        const errorMsg =
          error instanceof Error ? error.message : String(error);
        return {
          success: false,
          flag: null,
          message: `Exploit agent failed: ${errorMsg}`,
        };
      }
    },
  });
}

import { tool } from "ai";
import { z } from "zod";
import { writeFile } from "fs/promises";
import type { ToolContext } from "./types";
import { planFilePath } from "../../../plan";

const writePlanInputSchema = z.object({
  content: z.string().describe("The full markdown content of the pentest plan"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Writing initial pentest plan with recon findings')",
    ),
});

type WritePlanResult = {
  success: boolean;
  error: string;
  path: string;
};

export function writePlan(ctx: ToolContext) {
  return tool({
    description: `Write or update the pentest plan file for this session.

The plan is stored at a fixed path in the session directory (plan.md).
Always provide the complete plan content — the file is overwritten each time.

Required plan sections:
- **Objective** — engagement goals
- **Scope** — in-scope targets, exclusions
- **Reconnaissance Findings** — tech stack, endpoints, auth mechanisms discovered
- **Attack Surface Map** — entry points ranked by exposure
- **Prioritized Attack Vectors** — ordered by impact, with endpoint, vuln class, rationale, test approach per vector
- **Testing Methodology** — concrete techniques/payloads per vector (OWASP categories)
- **Estimated Action Tiers** — anticipated T1-T5 action counts so the operator can make an informed approval`,
    inputSchema: writePlanInputSchema,
    execute: async ({ content }): Promise<WritePlanResult> => {
      const planPath = planFilePath(ctx.session.rootPath);
      console.error(
        `[write_plan] enter: contentLen=${content.length}, path=${planPath}`,
      );
      try {
        await writeFile(planPath, content, "utf-8");
        console.error(`[write_plan] done`);
        return { success: true, error: "", path: planPath };
      } catch (err: unknown) {
        console.error(`[write_plan] error: ${err}`);
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          path: planPath,
        };
      }
    },
  });
}

import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

const checkpointInputSchema = z.object({
  discoveredSurface: z
    .array(z.string())
    .describe("Endpoints, services, and technologies discovered so far"),
  credentialsObtained: z
    .array(z.string())
    .describe(
      "Credentials, tokens, or auth material obtained (redact secrets)",
    ),
  confirmedVulnerabilities: z
    .array(z.string())
    .describe("Vulnerabilities confirmed with evidence"),
  actionsAttempted: z
    .array(
      z.object({
        description: z.string(),
        outcome: z.enum(["success", "failure", "partial", "in-progress"]),
      }),
    )
    .describe("What you've tried and the outcome of each"),
  nextSteps: z
    .array(
      z.object({
        action: z.string(),
        rationale: z.string(),
        priority: z.enum(["high", "medium", "low"]),
      }),
    )
    .describe("What you plan to do next, ordered by priority"),
  blockers: z
    .array(z.string())
    .describe("Anything blocking progress — errors, missing info, dead ends"),
  assessment: z
    .string()
    .describe("Overall assessment of the engagement so far"),
});

export function checkpointState(ctx: ToolContext) {
  return tool({
    description:
      "Record a structured snapshot of your current understanding of the target, " +
      "what you've tried, what worked, what's blocked, and what you plan to do next. " +
      "Call this after completing a phase of work (e.g., after recon, after finding " +
      "a vulnerability, when changing strategy). This does not affect your workflow — " +
      "it's purely for observability.",
    inputSchema: checkpointInputSchema,
    execute: async ({
      discoveredSurface,
      credentialsObtained,
      confirmedVulnerabilities,
      actionsAttempted,
      nextSteps,
      blockers,
      assessment,
    }) => {
      if (!ctx.traceWriter) {
        return "Checkpoint skipped — trace writer not available.";
      }

      ctx.traceWriter.appendCheckpoint({
        targetState: {
          discoveredSurface,
          credentialsObtained,
          confirmedVulnerabilities,
        },
        actionsAttempted,
        nextSteps,
        blockers,
        assessment,
      });

      return "Checkpoint recorded.";
    },
  });
}

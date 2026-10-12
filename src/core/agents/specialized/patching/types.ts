import { z } from "zod";
import type { SpecializedAgentInput } from "../../offSecAgent";

/**
 * Structured result returned by the patching agent via the `response` tool.
 */
export const PatchResultSchema = z.object({
  filesChanged: z.array(
    z.object({
      filePath: z.string().describe("Path to the file that was changed"),
      changesDescription: z
        .string()
        .describe("Detailed description of the changes made to the file"),
    }),
  ),
  prTitle: z.string().describe("Title for the pull request"),
  prDescription: z.string().describe("Description for the pull request"),
});

export type PatchResult = z.infer<typeof PatchResultSchema>;

/**
 * Vulnerability details passed to the patching agent.
 */
export interface VulnerabilityDetails {
  name: string;
  severity: string;
  description: string;
  location?: string;
  startLineNumber?: number | null;
  endLineNumber?: number | null;
  cweMapping?: string[];
  dataflowAnalysis?: unknown;
  poc?: {
    fileName: string;
    contents: string;
  };
}

/**
 * Input for the PatchingAgent constructor.
 */
export interface PatchingAgentInput extends SpecializedAgentInput {
  /** Root path of the cloned repository */
  cwd: string;

  /** Vulnerability details to patch */
  vulnerability: VulnerabilityDetails;
}

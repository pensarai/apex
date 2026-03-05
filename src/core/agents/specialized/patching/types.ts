import { z } from "zod";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
import type { UnifiedSandbox } from "../../offSecAgent/tools/sandbox";

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

  /**
   * Optional pre-configured sandbox for isolated code execution.
   *
   * When provided, tools like `execute_command`, `create_file`, and
   * `update_file` automatically route operations through the sandbox
   * instead of the local filesystem.
   *
   * The sandbox should be fully set up before passing it in (repo cloned,
   * dev environment started, etc.).
   */
  sandbox?: UnifiedSandbox;
}

import { z } from "zod";
import type { SubAgentConfig, SubAgentManifest } from "../subagent/types";

export interface OrchestratorInput {
  attackSurfacePath: string;
  session: {
    id: string;
    rootPath: string;
  };
  whiteboxMode?: boolean;
  sourceCodePath?: string;
  focusEndpoint?: string;
  concurrencyLimit?: number;
  abortSignal?: AbortSignal;
}

export interface OrchestratorResult {
  success: boolean;
  manifest: SubAgentManifest;
  manifestPath: string;
  error?: string;
}

export const SpawnSubagentSchema = z.object({
  endpoint: z.string().describe("Target endpoint URL"),
  vulnerabilityClass: z.string().describe("Vulnerability class to test"),
  context: z.record(z.string(), z.any()).optional().describe("Additional context for the sub-agent"),
  priority: z.enum(["critical", "high", "medium", "low"]).describe("Priority level"),
  rationale: z.string().describe("Why this sub-agent should be spawned"),
});

export type SpawnSubagentInput = z.infer<typeof SpawnSubagentSchema>;

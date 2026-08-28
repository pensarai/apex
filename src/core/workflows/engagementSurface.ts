import { type ToolSet, tool } from "ai";
import { z } from "zod";

export interface EngagementSurfaceTargetSummary {
  id: string;
  applicationId: string;
  applicationName: string;
  target: string;
  type?: string | null;
  transport?: string | null;
  riskScore?: number | null;
  authenticationRequired?: boolean | null;
}

export interface EngagementSurfaceTargetDetail
  extends EngagementSurfaceTargetSummary {
  applicationDescription?: string | null;
  applicationFramework?: string | null;
  description?: string | null;
  location?: string | null;
  businessLogic?: string | null;
  threatModel?: string | null;
  objectives: string[];
  transportMetadata?: unknown;
}

export interface EngagementSurfaceSearchInput {
  query?: string;
  applicationId?: string;
  type?: string;
  transport?: string;
  minRiskScore?: number;
  authenticationRequired?: boolean;
  limit: number;
  offset: number;
}

export interface EngagementSurfaceProvider {
  search(input: EngagementSurfaceSearchInput): Promise<{
    targets: EngagementSurfaceTargetSummary[];
    total: number;
  }>;
  getTarget(id: string): Promise<EngagementSurfaceTargetDetail | null>;
}

export const ENGAGEMENT_SURFACE_TOOL_NAMES = [
  "search_engagement_surface",
  "get_engagement_target",
] as const;

export function createEngagementSurfaceTools(
  provider: EngagementSurfaceProvider,
): ToolSet {
  return {
    search_engagement_surface: tool({
      description:
        "List or search the immutable attack-surface snapshot authorized for this engagement. Use filters and pagination instead of loading the whole surface into context.",
      inputSchema: z.object({
        query: z.string().min(1).optional(),
        applicationId: z.string().min(1).optional(),
        type: z.string().min(1).optional(),
        transport: z.string().min(1).optional(),
        minRiskScore: z.number().min(0).max(10).optional(),
        authenticationRequired: z.boolean().optional(),
        limit: z.number().int().min(1).max(100).default(25),
        offset: z.number().int().min(0).default(0),
        toolCallDescription: z.string(),
      }),
      execute: async ({ toolCallDescription: _, ...input }) => ({
        success: true,
        ...(await provider.search(input)),
      }),
    }),
    get_engagement_target: tool({
      description:
        "Read the full immutable context for one authorized engagement target, including its threat model, objectives, intended business logic, authentication requirements, and transport metadata.",
      inputSchema: z.object({
        targetId: z.string().min(1),
        toolCallDescription: z.string(),
      }),
      execute: async ({ targetId }) => {
        const target = await provider.getTarget(targetId);
        return target
          ? { success: true, target }
          : {
              success: false,
              message: `Unknown engagement target: ${targetId}`,
            };
      },
    }),
  };
}

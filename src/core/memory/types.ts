import { z } from "zod";

export const MemoryToolSchema = z.object({
  name: z.string(),
  code: z.string(),
  language: z.enum(["bun", "python"]),
  description: z.string(),
  tags: z.array(z.string()),
  createdAt: z.string(),
  usageCount: z.number().default(0),
});

export type MemoryTool = z.infer<typeof MemoryToolSchema>;

export const TechniqueSchema = z.object({
  id: z.string(),
  vulnerabilityClass: z.string(),
  payload: z.string(),
  context: z.string(),
  successRate: z.number(),
  usageCount: z.number().default(0),
  lastUsed: z.string().optional(),
  tags: z.array(z.string()),
});

export type Technique = z.infer<typeof TechniqueSchema>;

export const MemoryFindingSchema = z.object({
  id: z.string(),
  title: z.string(),
  vulnerabilityClass: z.string(),
  endpoint: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  technique: z.string(),
  createdAt: z.string(),
});

export type MemoryFinding = z.infer<typeof MemoryFindingSchema>;

export const MemoryIndexSchema = z.object({
  workspace: z.string(),
  lastUpdated: z.string(),
  tools: z.array(z.string()),
  techniques: z.array(z.string()),
  findings: z.array(z.string()),
});

export type MemoryIndex = z.infer<typeof MemoryIndexSchema>;

export interface SearchResult {
  type: "tool" | "technique" | "finding";
  id: string;
  score: number;
  data: MemoryTool | Technique | MemoryFinding;
}

import { apiRequest } from "./apiClient";

export const KNOWLEDGE_CATEGORIES = [
  "false_positive_pattern",
  "technology_context",
  "testing_history",
  "user_note",
  "agent_learning",
] as const;

export const KNOWLEDGE_STATUSES = ["active", "stale", "archived"] as const;

export type KnowledgeCategory = (typeof KNOWLEDGE_CATEGORIES)[number];
export type KnowledgeStatus = (typeof KNOWLEDGE_STATUSES)[number];

export interface KnowledgeEntry {
  id: string;
  title: string;
  content: string;
  category: KnowledgeCategory;
  status: KnowledgeStatus;
  source: string;
  tags: string[];
  confidence: string | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface KnowledgeInput {
  title?: string;
  content?: string;
  category?: KnowledgeCategory;
  status?: KnowledgeStatus;
  tags?: string[];
}

export async function listKnowledge(filters?: {
  category?: string;
  status?: string;
  tags?: string[];
}): Promise<KnowledgeEntry[]> {
  const params = new URLSearchParams();
  if (filters?.category) params.set("category", filters.category);
  if (filters?.status) params.set("status", filters.status);
  if (filters?.tags?.length) params.set("tags", filters.tags.join(","));
  const qs = params.toString();
  return apiRequest<KnowledgeEntry[]>("GET", `/knowledge${qs ? `?${qs}` : ""}`);
}

export async function getKnowledge(id: string): Promise<KnowledgeEntry> {
  return apiRequest<KnowledgeEntry>("GET", `/knowledge/${id}`);
}

export async function createKnowledge(
  input: KnowledgeInput,
): Promise<KnowledgeEntry> {
  return apiRequest<KnowledgeEntry>("POST", "/knowledge", input);
}

export async function updateKnowledge(
  id: string,
  input: KnowledgeInput,
): Promise<KnowledgeEntry> {
  return apiRequest<KnowledgeEntry>("PATCH", `/knowledge/${id}`, input);
}

export async function archiveKnowledge(id: string): Promise<KnowledgeEntry> {
  return apiRequest<KnowledgeEntry>("DELETE", `/knowledge/${id}`);
}

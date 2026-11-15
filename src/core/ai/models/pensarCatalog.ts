import { getPensarGatewayUrl } from "../../api/constants";
import type { Config } from "../../config/config";
import type { ModelInfo } from "../ai";

type CatalogModel = ModelInfo & {
  maxOutputTokens?: number;
  reasoning?: {
    mandatory?: boolean;
    default_enabled?: boolean;
    supported_efforts?: string[] | null;
    default_effort?: string;
  };
};
const models = new Map<string, CatalogModel>();
let cached:
  | { key: string; expires: number; models: CatalogModel[] }
  | undefined;

export function getPensarCatalogModel(id: string): CatalogModel | undefined {
  return models.get(id);
}

export async function loadPensarCatalog(
  cfg: Pick<
    Config,
    "accessToken" | "pensarAPIKey" | "gatewayUrl" | "workspaceId"
  >,
): Promise<CatalogModel[]> {
  const token = cfg.accessToken || cfg.pensarAPIKey;
  if (!token) return [];
  const baseUrl = cfg.gatewayUrl || getPensarGatewayUrl();
  const key = `${baseUrl}:${cfg.workspaceId}:${token}`;
  if (cached?.key === key && cached.expires > Date.now()) return cached.models;
  const response = await fetch(`${baseUrl}/gateway/models`, {
    headers: {
      Authorization: `Bearer ${token}`,
      ...(cfg.workspaceId ? { "X-Workspace-Id": cfg.workspaceId } : {}),
    },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok)
    throw new Error(`Could not load Pensar models (${response.status}).`);
  const body = (await response.json()) as { data?: unknown };
  if (!Array.isArray(body.data))
    throw new Error("Invalid Pensar model catalog.");
  const parsed = body.data.map((row: Record<string, unknown>): CatalogModel => {
    if (typeof row.id !== "string" || !/^[^\s/]+\/[^\s/]+$/.test(row.id))
      throw new Error("Invalid Pensar model ID.");
    const top = row.top_provider as
      | { max_completion_tokens?: number }
      | undefined;
    const model: CatalogModel = {
      id: `pensar:${row.id}`,
      name: typeof row.name === "string" ? row.name : row.id,
      provider: "pensar",
      ...(typeof row.context_length === "number" && row.context_length > 0
        ? { contextLength: row.context_length }
        : {}),
      ...(top?.max_completion_tokens && top.max_completion_tokens > 0
        ? { maxOutputTokens: top.max_completion_tokens }
        : {}),
      ...(row.reasoning && typeof row.reasoning === "object"
        ? { reasoning: row.reasoning as CatalogModel["reasoning"] }
        : {}),
    };
    return model;
  });
  for (const model of parsed) models.set(model.id, model);
  cached = { key, expires: Date.now() + 300_000, models: parsed };
  return parsed;
}

import { getPensarApiUrl } from "./constants";
import { ensureValidToken } from "../auth";
import type { Config } from "../config/config";

export type UsagePeriod = "week" | "month" | "year";

export interface UsageDataPoint {
  date: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cost: number;
}

export interface UsageSummary {
  totalRequests: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalTokens: number;
  totalCost: number;
  averageDailyRequests: number;
  averageDailyCost: number;
}

export interface CiUsageResponse {
  period: UsagePeriod;
  model: string | null;
  data: UsageDataPoint[];
  summary: UsageSummary;
  models: string[];
}

function buildAuthHeaders(
  token: string,
  tokenType: "workos" | "legacy",
  workspaceId?: string | null,
): Record<string, string> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  };
  if (tokenType === "workos" && workspaceId) {
    headers["X-Workspace-Id"] = workspaceId;
  }
  return headers;
}

export async function fetchCiUsage(
  appConfig: Config,
  period: UsagePeriod,
  model?: string | null,
): Promise<CiUsageResponse | null> {
  const tokenResult = await ensureValidToken({
    accessToken: appConfig.accessToken,
    refreshToken: appConfig.refreshToken,
    pensarAPIKey: appConfig.pensarAPIKey,
  });

  if (!tokenResult) return null;

  try {
    const apiUrl = getPensarApiUrl();
    const headers = buildAuthHeaders(
      tokenResult.token,
      tokenResult.type,
      appConfig.workspaceId,
    );

    const params = new URLSearchParams({ period });
    if (model) params.set("model", model);

    const response = await fetch(
      `${apiUrl}/api/cli/usage/history?${params.toString()}`,
      { method: "GET", headers },
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch usage: ${response.status}`);
    }

    return (await response.json()) as CiUsageResponse;
  } catch {
    return null;
  }
}

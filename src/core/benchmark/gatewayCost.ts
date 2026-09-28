import { normalizeStepUsage } from "../ai";

export type CostBenchGateway = "openrouter" | "concentrate";

export type ReferenceTokenRates = {
  inputPerMillion: number;
  outputPerMillion: number;
  cacheReadPerMillion: number;
  cacheWritePerMillion: number;
  capturedAt: string;
  source: string;
};

export type GatewayStepCost = {
  gateway: CostBenchGateway;
  providerCostUsd: number;
  byok: boolean | undefined;
  servedModel: string | undefined;
  routes: string[];
  inputTokens: number;
  outputTokens: number;
  reasoningTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  referenceCostUsd: number;
};

type StepLike = {
  usage?: {
    inputTokens?: number;
    outputTokens?: number;
    inputTokenDetails?: {
      cacheReadTokens?: number;
      cacheWriteTokens?: number;
    };
    outputTokenDetails?: {
      reasoningTokens?: number;
    };
  };
  providerMetadata?: unknown;
  response?: { modelId?: string };
};

export class MissingGatewayCostError extends Error {
  constructor(gateway: CostBenchGateway) {
    super(
      `Successful ${gateway} response did not include billed cost metadata`,
    );
    this.name = "MissingGatewayCostError";
  }
}

export class CostBudgetExceededError extends Error {
  readonly limitUsd: number;
  readonly spentUsd: number;

  constructor(limitUsd: number, spentUsd: number) {
    super(
      `Cost budget exceeded: spent $${spentUsd.toFixed(6)} of $${limitUsd.toFixed(2)}`,
    );
    this.name = "CostBudgetExceededError";
    this.limitUsd = limitUsd;
    this.spentUsd = spentUsd;
  }
}

export class CostBudget {
  readonly limitUsd: number;
  private _spentUsd = 0;

  constructor(limitUsd: number) {
    if (!Number.isFinite(limitUsd) || limitUsd <= 0) {
      throw new Error("Cost budget must be a finite positive number");
    }
    this.limitUsd = limitUsd;
  }

  get spentUsd(): number {
    return this._spentUsd;
  }

  get remainingUsd(): number {
    return Math.max(0, this.limitUsd - this._spentUsd);
  }

  assertCanStart(reserveUsd: number): void {
    requireNonNegativeFinite(reserveUsd, "reserveUsd");
    if (this._spentUsd + reserveUsd > this.limitUsd) {
      throw new CostBudgetExceededError(this.limitUsd, this._spentUsd);
    }
  }

  record(costUsd: number): void {
    requireNonNegativeFinite(costUsd, "costUsd");
    this._spentUsd += costUsd;
    if (this._spentUsd > this.limitUsd) {
      throw new CostBudgetExceededError(this.limitUsd, this._spentUsd);
    }
  }
}

function recordOf(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function nonNegativeFinite(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : undefined;
}

function requireNonNegativeFinite(value: number, field: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${field} must be a finite non-negative number`);
  }
}

function calculateReferenceCost(
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens: number;
    cacheWriteTokens: number;
  },
  rates: ReferenceTokenRates,
): number {
  const uncachedInput = Math.max(
    0,
    usage.inputTokens - usage.cacheReadTokens - usage.cacheWriteTokens,
  );
  return (
    (uncachedInput / 1_000_000) * rates.inputPerMillion +
    (usage.outputTokens / 1_000_000) * rates.outputPerMillion +
    (usage.cacheReadTokens / 1_000_000) * rates.cacheReadPerMillion +
    (usage.cacheWriteTokens / 1_000_000) * rates.cacheWritePerMillion
  );
}

function openRouterCost(metadata: Record<string, unknown>): {
  cost: number | undefined;
  byok: boolean | undefined;
  servedModel: undefined;
  routes: string[];
} {
  const openrouter = recordOf(metadata.openrouter);
  const usage = recordOf(openrouter?.usage);
  const provider =
    typeof openrouter?.provider === "string" ? openrouter.provider : undefined;
  const byokValue = usage?.isByok ?? usage?.is_byok;
  return {
    cost: nonNegativeFinite(usage?.cost),
    byok: typeof byokValue === "boolean" ? byokValue : undefined,
    servedModel: undefined,
    routes: provider ? [provider] : [],
  };
}

function concentrateCost(metadata: Record<string, unknown>): {
  cost: number | undefined;
  byok: boolean | undefined;
  servedModel: string | undefined;
  routes: string[];
} {
  const concentrate = recordOf(metadata.concentrate);
  const cost = recordOf(concentrate?.cost);
  const breakdown = recordOf(cost?.breakdown);
  const servedModel =
    typeof concentrate?.model === "string" ? concentrate.model : undefined;
  const byokValue = cost?.byok;
  const routes = breakdown ? Object.keys(breakdown).sort() : [];
  if (routes.length === 0 && servedModel) routes.push(servedModel);
  return {
    cost: nonNegativeFinite(cost?.total),
    byok: typeof byokValue === "boolean" ? byokValue : undefined,
    servedModel,
    routes,
  };
}

export function extractGatewayStepCost(
  gateway: CostBenchGateway,
  step: StepLike,
  referenceRates: ReferenceTokenRates,
): GatewayStepCost {
  const metadata = recordOf(step.providerMetadata) ?? {};
  const normalized = normalizeStepUsage(step);
  const reasoningTokens =
    nonNegativeFinite(step.usage?.outputTokenDetails?.reasoningTokens) ?? 0;
  const extracted =
    gateway === "openrouter"
      ? openRouterCost(metadata)
      : concentrateCost(metadata);
  if (extracted.cost === undefined) {
    throw new MissingGatewayCostError(gateway);
  }

  const servedModel = extracted.servedModel ?? step.response?.modelId;
  const usage = { ...normalized, reasoningTokens };
  return {
    gateway,
    providerCostUsd: extracted.cost,
    byok: extracted.byok,
    servedModel,
    routes: extracted.routes,
    ...usage,
    referenceCostUsd: calculateReferenceCost(usage, referenceRates),
  };
}

export function parseOpenRouterReferenceRates(
  payload: unknown,
  capturedAt: string,
  source = "https://openrouter.ai/api/v1/models",
): ReferenceTokenRates {
  const root = recordOf(payload);
  const data = Array.isArray(root?.data) ? root.data : [];
  const model = data
    .map(recordOf)
    .find((candidate) => candidate?.id === "z-ai/glm-5.3");
  const pricing = recordOf(model?.pricing);
  const perToken = (field: string): number => {
    const raw = pricing?.[field];
    const parsed =
      typeof raw === "string" || typeof raw === "number"
        ? Number(raw)
        : Number.NaN;
    if (!Number.isFinite(parsed) || parsed < 0) {
      throw new Error(`OpenRouter GLM 5.3 catalog is missing pricing.${field}`);
    }
    return parsed;
  };

  return {
    inputPerMillion: perToken("prompt") * 1_000_000,
    outputPerMillion: perToken("completion") * 1_000_000,
    cacheReadPerMillion: perToken("input_cache_read") * 1_000_000,
    cacheWritePerMillion: 0,
    capturedAt,
    source,
  };
}

export function calculateOpenRouterFundingFee(
  creditPurchaseUsd: number,
  rate = 0.055,
  minimumUsd = 0.8,
): number {
  if (!Number.isFinite(creditPurchaseUsd) || creditPurchaseUsd <= 0) {
    throw new Error("creditPurchaseUsd must be a finite positive number");
  }
  requireNonNegativeFinite(rate, "rate");
  requireNonNegativeFinite(minimumUsd, "minimumUsd");
  return Math.max(creditPurchaseUsd * rate, minimumUsd);
}

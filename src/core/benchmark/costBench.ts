import { stepCountIs, tool } from "ai";
import { z } from "zod";
import { streamResponse } from "../ai";
import {
  type CostBenchGateway,
  CostBudget,
  CostBudgetExceededError,
  extractGatewayStepCost,
  type GatewayStepCost,
  type ReferenceTokenRates,
} from "./gatewayCost";

export const COST_BENCH_MODELS: Record<CostBenchGateway, string> = {
  openrouter: "z-ai/glm-5.3",
  concentrate: "concentrate:glm-5.3",
};

export type CostBenchCaseId =
  | "exact-reasoning"
  | "structured-extraction"
  | "tool-call"
  | "security-analysis"
  | "long-context-cache";

export type CostBenchSample = {
  caseId: CostBenchCaseId;
  gateway: CostBenchGateway;
  requestedModel: string;
  repetition: number;
  status: "passed" | "failed" | "error";
  validationError?: string;
  error?: string;
  responseText: string;
  toolCalls: Array<{ name: string; input: unknown }>;
  servedModels: string[];
  routes: string[];
  byok: boolean | undefined;
  inputTokens: number;
  outputTokens: number;
  reasoningTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  providerCostUsd: number;
  referenceCostUsd: number;
  timeToFirstTokenMs: number | null;
  totalLatencyMs: number;
  outputTokensPerSecond: number | null;
  stepCount: number;
  startedAt: string;
};

export type CostBenchResult = {
  benchmark: "glm-5.3-gateway-cost";
  startedAt: string;
  completedAt: string;
  repetitions: number;
  budgetUsd: number;
  spentUsd: number;
  referenceRates: ReferenceTokenRates;
  models: Record<CostBenchGateway, string>;
  cases: CostBenchCaseId[];
  samples: CostBenchSample[];
  stoppedReason?: string;
};

export type CostBenchConfig = {
  openRouterApiKey: string;
  concentrateApiKey: string;
  referenceRates: ReferenceTokenRates;
  repetitions: number;
  budgetUsd: number;
  reservePerCallUsd?: number;
  cases?: CostBenchCaseId[];
};

type BenchScenario = {
  id: CostBenchCaseId;
  system: string;
  prompt: string;
  maxOutputTokens: number;
};

const ALL_CASES: CostBenchCaseId[] = [
  "exact-reasoning",
  "structured-extraction",
  "tool-call",
  "security-analysis",
  "long-context-cache",
];

function longContextPrompt(): string {
  const records = Array.from({ length: 1_500 }, (_, index) => {
    const id = String(index + 1).padStart(4, "0");
    const marker = index === 1_237 ? "cobalt-heron-927" : `filler-${id}`;
    return `record=${id}; region=west; marker=${marker}; status=active`;
  }).join("\n");
  return [
    "Read the records and return only the marker from record 1238.",
    "Format exactly: NEEDLE=<marker>",
    "",
    records,
  ].join("\n");
}

function scenarioFor(id: CostBenchCaseId): BenchScenario {
  switch (id) {
    case "exact-reasoning":
      return {
        id,
        system:
          "Solve the task privately. Return only the requested final marker.",
        prompt:
          "A service handles 37 requests per second for 19 seconds, then retries exactly 28 failed requests once. How many request attempts occur? Return exactly ANSWER=<integer>.",
        maxOutputTokens: 512,
      };
    case "structured-extraction":
      return {
        id,
        system: "Return valid JSON only, with no markdown fences or prose.",
        prompt:
          'From "Account ACME-42 exposes ports 8443 and 443. Risk is HIGH.", return exactly this schema: {"account":string,"risk":"high"|"low","ports":number[]}. Sort ports ascending.',
        maxOutputTokens: 512,
      };
    case "tool-call":
      return {
        id,
        system:
          "Use the provided tool exactly once, then return only QUOTE=<total>.",
        prompt:
          "Calculate a quote for quantity 7 at unit price 12 by calling quote_cost.",
        maxOutputTokens: 512,
      };
    case "security-analysis":
      return {
        id,
        system:
          "Identify only the deliberately planted issues. Return one final line in the requested format.",
        prompt: [
          "Review this handler:",
          "```ts",
          'const ADMIN_TOKEN = "prod-secret";',
          "export async function login(req, db) {",
          "  const { email, password } = req.body;",
          '  console.log("login", email, password);',
          '  return db.query("SELECT * FROM users WHERE email = \'" + email + "\'");',
          "}",
          "```",
          "Return exactly FINDINGS=HARDCODED_SECRET,PLAINTEXT_PASSWORD_LOG,SQL_INJECTION",
          "with those three identifiers in any order and no extras.",
        ].join("\n"),
        maxOutputTokens: 768,
      };
    case "long-context-cache":
      return {
        id,
        system:
          "Perform exact retrieval from the supplied records. Return only the requested marker.",
        prompt: longContextPrompt(),
        maxOutputTokens: 256,
      };
  }
}

function parseJsonObject(text: string): Record<string, unknown> | undefined {
  const trimmed = text
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/```$/, "");
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

export function validateCostBenchOutput(
  caseId: CostBenchCaseId,
  responseText: string,
  toolCalls: Array<{ name: string; input: unknown }>,
): string | undefined {
  switch (caseId) {
    case "exact-reasoning":
      return responseText.trim() === "ANSWER=731"
        ? undefined
        : "Expected exactly ANSWER=731";
    case "structured-extraction": {
      const parsed = parseJsonObject(responseText);
      const ports = parsed?.ports;
      return parsed?.account === "ACME-42" &&
        parsed.risk === "high" &&
        Array.isArray(ports) &&
        ports.length === 2 &&
        ports[0] === 443 &&
        ports[1] === 8443
        ? undefined
        : "Structured extraction did not match the expected object";
    }
    case "tool-call": {
      const quoteCalls = toolCalls.filter(({ name }) => name === "quote_cost");
      const input = quoteCalls[0]?.input as
        | { quantity?: unknown; unitPrice?: unknown }
        | undefined;
      return quoteCalls.length === 1 &&
        input?.quantity === 7 &&
        input.unitPrice === 12 &&
        responseText.trim() === "QUOTE=84"
        ? undefined
        : "Expected one valid quote_cost call followed by QUOTE=84";
    }
    case "security-analysis": {
      const line = responseText
        .trim()
        .split("\n")
        .find((candidate) => candidate.startsWith("FINDINGS="));
      const findings = new Set(
        line
          ?.slice("FINDINGS=".length)
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean) ?? [],
      );
      const expected = [
        "HARDCODED_SECRET",
        "PLAINTEXT_PASSWORD_LOG",
        "SQL_INJECTION",
      ];
      return findings.size === expected.length &&
        expected.every((finding) => findings.has(finding))
        ? undefined
        : "Security findings did not match the three planted issues";
    }
    case "long-context-cache":
      return responseText.trim() === "NEEDLE=cobalt-heron-927"
        ? undefined
        : "Long-context retrieval missed the planted marker";
  }
}

function aggregateStepCosts(
  stepCosts: GatewayStepCost[],
): Pick<
  CostBenchSample,
  | "servedModels"
  | "routes"
  | "byok"
  | "inputTokens"
  | "outputTokens"
  | "reasoningTokens"
  | "cacheReadTokens"
  | "cacheWriteTokens"
  | "providerCostUsd"
  | "referenceCostUsd"
> {
  const byokValues = new Set(
    stepCosts
      .map(({ byok }) => byok)
      .filter((value): value is boolean => value !== undefined),
  );
  return {
    servedModels: [
      ...new Set(
        stepCosts
          .map(({ servedModel }) => servedModel)
          .filter((value): value is string => Boolean(value)),
      ),
    ].sort(),
    routes: [...new Set(stepCosts.flatMap(({ routes }) => routes))].sort(),
    byok: byokValues.size === 1 ? [...byokValues][0] : undefined,
    inputTokens: stepCosts.reduce((sum, step) => sum + step.inputTokens, 0),
    outputTokens: stepCosts.reduce((sum, step) => sum + step.outputTokens, 0),
    reasoningTokens: stepCosts.reduce(
      (sum, step) => sum + step.reasoningTokens,
      0,
    ),
    cacheReadTokens: stepCosts.reduce(
      (sum, step) => sum + step.cacheReadTokens,
      0,
    ),
    cacheWriteTokens: stepCosts.reduce(
      (sum, step) => sum + step.cacheWriteTokens,
      0,
    ),
    providerCostUsd: stepCosts.reduce(
      (sum, step) => sum + step.providerCostUsd,
      0,
    ),
    referenceCostUsd: stepCosts.reduce(
      (sum, step) => sum + step.referenceCostUsd,
      0,
    ),
  };
}

async function runSample(params: {
  gateway: CostBenchGateway;
  scenario: BenchScenario;
  repetition: number;
  apiKey: string;
  referenceRates: ReferenceTokenRates;
  budget: CostBudget;
}): Promise<CostBenchSample> {
  const { gateway, scenario, repetition, apiKey, referenceRates, budget } =
    params;
  const model = COST_BENCH_MODELS[gateway];
  const startedAt = new Date().toISOString();
  const startedMs = performance.now();
  let firstTokenMs: number | null = null;
  const toolCalls: Array<{ name: string; input: unknown }> = [];
  const stepCosts: GatewayStepCost[] = [];
  let responseText = "";

  const tools =
    scenario.id === "tool-call"
      ? {
          quote_cost: tool({
            description: "Calculate quantity multiplied by unit price.",
            inputSchema: z.object({
              quantity: z.literal(7),
              unitPrice: z.literal(12),
            }),
            execute: async ({
              quantity,
              unitPrice,
            }: {
              quantity: 7;
              unitPrice: 12;
            }) => ({ total: quantity * unitPrice }),
          }),
        }
      : undefined;

  try {
    const response = streamResponse({
      model,
      system: scenario.system,
      prompt: scenario.prompt,
      maxOutputTokens: scenario.maxOutputTokens,
      authConfig:
        gateway === "openrouter"
          ? { openRouterAPIKey: apiKey }
          : { concentrateAPIKey: apiKey },
      tools,
      stopWhen: tools ? stepCountIs(3) : stepCountIs(1),
      silent: true,
      usageRecorder: async () => {},
      onStepFinish: (step) => {
        const cost = extractGatewayStepCost(gateway, step, referenceRates);
        budget.record(cost.providerCostUsd);
        stepCosts.push(cost);
      },
    });

    for await (const part of response.fullStream) {
      if (
        firstTokenMs === null &&
        (part.type === "reasoning-delta" ||
          part.type === "text-delta" ||
          part.type === "tool-input-delta" ||
          part.type === "tool-call")
      ) {
        firstTokenMs = performance.now();
      }
      if (part.type === "text-delta") responseText += part.text;
      if (part.type === "tool-call") {
        toolCalls.push({ name: part.toolName, input: part.input });
      }
    }

    const totals = aggregateStepCosts(stepCosts);
    const totalLatencyMs = performance.now() - startedMs;
    const validationError = validateCostBenchOutput(
      scenario.id,
      responseText,
      toolCalls,
    );
    const generationSeconds =
      firstTokenMs === null ? 0 : (performance.now() - firstTokenMs) / 1_000;
    return {
      caseId: scenario.id,
      gateway,
      requestedModel: model,
      repetition,
      status: validationError ? "failed" : "passed",
      ...(validationError ? { validationError } : {}),
      responseText,
      toolCalls,
      ...totals,
      timeToFirstTokenMs:
        firstTokenMs === null ? null : firstTokenMs - startedMs,
      totalLatencyMs,
      outputTokensPerSecond:
        generationSeconds > 0 ? totals.outputTokens / generationSeconds : null,
      stepCount: stepCosts.length,
      startedAt,
    };
  } catch (error) {
    if (error instanceof CostBudgetExceededError) throw error;
    const totals = aggregateStepCosts(stepCosts);
    return {
      caseId: scenario.id,
      gateway,
      requestedModel: model,
      repetition,
      status: "error",
      error: error instanceof Error ? error.message : String(error),
      responseText,
      toolCalls,
      ...totals,
      timeToFirstTokenMs:
        firstTokenMs === null ? null : firstTokenMs - startedMs,
      totalLatencyMs: performance.now() - startedMs,
      outputTokensPerSecond: null,
      stepCount: stepCosts.length,
      startedAt,
    };
  }
}

export async function runCostBench(
  config: CostBenchConfig,
): Promise<CostBenchResult> {
  if (!Number.isSafeInteger(config.repetitions) || config.repetitions <= 0) {
    throw new Error("repetitions must be a positive safe integer");
  }
  if (!config.openRouterApiKey.trim() || !config.concentrateApiKey.trim()) {
    throw new Error(
      "OPENROUTER_API_KEY and CONCENTRATE_API_KEY are both required",
    );
  }
  const cases = config.cases ?? ALL_CASES;
  const budget = new CostBudget(config.budgetUsd);
  const reservePerCallUsd = config.reservePerCallUsd ?? 0.25;
  const startedAt = new Date().toISOString();
  const samples: CostBenchSample[] = [];
  let stoppedReason: string | undefined;

  try {
    for (let repetition = 1; repetition <= config.repetitions; repetition++) {
      for (let caseIndex = 0; caseIndex < cases.length; caseIndex++) {
        const caseId = cases[caseIndex];
        if (!caseId) continue;
        const gateways: CostBenchGateway[] =
          (repetition + caseIndex) % 2 === 0
            ? ["openrouter", "concentrate"]
            : ["concentrate", "openrouter"];
        for (const gateway of gateways) {
          budget.assertCanStart(reservePerCallUsd);
          samples.push(
            await runSample({
              gateway,
              scenario: scenarioFor(caseId),
              repetition,
              apiKey:
                gateway === "openrouter"
                  ? config.openRouterApiKey
                  : config.concentrateApiKey,
              referenceRates: config.referenceRates,
              budget,
            }),
          );
        }
      }
    }
  } catch (error) {
    if (!(error instanceof CostBudgetExceededError)) throw error;
    stoppedReason = error.message;
  }

  return {
    benchmark: "glm-5.3-gateway-cost",
    startedAt,
    completedAt: new Date().toISOString(),
    repetitions: config.repetitions,
    budgetUsd: config.budgetUsd,
    spentUsd: budget.spentUsd,
    referenceRates: config.referenceRates,
    models: COST_BENCH_MODELS,
    cases,
    samples,
    ...(stoppedReason ? { stoppedReason } : {}),
  };
}

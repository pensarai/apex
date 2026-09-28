import { toJsonValue } from "./content";
import type {
  EvidenceAvailability,
  JsonValue,
  ProviderExtraV1,
} from "./schema";

export interface NativeSamplingEvidence {
  promptTokenIds: EvidenceAvailability<number[]>;
  completionTokenIds: EvidenceAvailability<number[]>;
  logprobs: EvidenceAvailability<number[]>;
  tokenizer: EvidenceAvailability<{ name: string; version?: string }>;
  extra: EvidenceAvailability<ProviderExtraV1>;
}

const NO_TOKEN_IDS =
  "the provider boundary does not expose numeric native token ids";

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function collectOpenAiLogprobs(
  value: unknown,
  probabilities: number[],
  entries: JsonValue[],
): void {
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectOpenAiLogprobs(entry, probabilities, entries);
    }
    return;
  }
  const record = asRecord(value);
  if (!record) return;
  if (typeof record.logprob === "number") {
    if (!Number.isFinite(record.logprob)) return;
    probabilities.push(record.logprob);
    entries.push(toJsonValue(record));
    return;
  }
  if (Array.isArray(record.content)) {
    collectOpenAiLogprobs(record.content, probabilities, entries);
  }
}

function openAiExtra(
  provider: string,
  openai: Record<string, unknown>,
  logprobEntries: JsonValue[],
): EvidenceAvailability<ProviderExtraV1> {
  const value: Record<string, JsonValue> = {};
  for (const key of [
    "responseId",
    "serviceTier",
    "acceptedPredictionTokens",
    "rejectedPredictionTokens",
  ]) {
    if (openai[key] !== undefined) value[key] = toJsonValue(openai[key]);
  }
  if (logprobEntries.length > 0) value.logprobEntries = logprobEntries;
  if (Object.keys(value).length === 0) {
    return {
      state: "omitted",
      reason: "the OpenAI adapter supplied no allowlisted native metadata",
    };
  }
  return {
    state: "available",
    value: {
      schema: "pensar.native_rollout_provider_extra.openai",
      version: 1,
      provider,
      value,
    },
  };
}

export function extractNativeSamplingEvidence(input: {
  provider: string;
  providerMetadata?: unknown;
}): NativeSamplingEvidence {
  const metadata = asRecord(input.providerMetadata);
  const openai = asRecord(metadata?.openai);
  const probabilities: number[] = [];
  const logprobEntries: JsonValue[] = [];
  const logprobsValue = openai?.logprobs;
  if (logprobsValue !== undefined) {
    collectOpenAiLogprobs(logprobsValue, probabilities, logprobEntries);
  }
  const explicitEmptyLogprobs =
    (Array.isArray(logprobsValue) && logprobsValue.length === 0) ||
    (Array.isArray(asRecord(logprobsValue)?.content) &&
      (asRecord(logprobsValue)?.content as unknown[]).length === 0);

  const openAiRoute = input.provider.toLowerCase().includes("openai");
  const logprobs: EvidenceAvailability<number[]> =
    probabilities.length > 0 || explicitEmptyLogprobs
      ? { state: "available", value: probabilities }
      : openAiRoute || openai !== undefined
        ? {
            state: "omitted",
            reason: "the OpenAI adapter did not return completion logprobs",
          }
        : {
            state: "unsupported",
            reason: "this provider route exposes no supported logprob field",
          };

  return {
    promptTokenIds: { state: "unsupported", reason: NO_TOKEN_IDS },
    completionTokenIds: { state: "unsupported", reason: NO_TOKEN_IDS },
    logprobs,
    tokenizer: {
      state: "unsupported",
      reason: "the provider boundary exposes no tokenizer identity",
    },
    extra:
      openai !== undefined
        ? openAiExtra(input.provider, openai, logprobEntries)
        : {
            state: "unsupported",
            reason:
              "this provider route has no documented native extra adapter",
          },
  };
}

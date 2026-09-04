import type { AttemptEvidence, AttemptTransport } from "./envelope";
import { ATTEMPT_TRANSPORTS, CACHE_BREAKPOINTS } from "./envelope";
import { InferenceAttemptValidationError } from "./errors";
import { type AttemptTokens, finalizeTokens, parseTokenCount } from "./tokens";

export interface TransportUsageInput {
  transport: AttemptTransport;
  usage?: unknown;
  providerMetadata?: unknown;
  providerRequestId?: string;
  cacheTtlSeconds?: number;
  cacheBreakpoint?: AttemptEvidence["cacheBreakpoint"];
}

export interface AdaptedUsage {
  tokens: AttemptTokens;
  evidence: AttemptEvidence;
}

export function adaptTransportUsage(input: TransportUsageInput): AdaptedUsage {
  if (!ATTEMPT_TRANSPORTS.includes(input.transport)) {
    throw new InferenceAttemptValidationError(
      "invalid-envelope",
      `unknown transport ${String(input.transport)}`,
    );
  }

  const usage = asRecord(input.usage, "usage");
  const meta = asRecord(input.providerMetadata, "providerMetadata");
  const tokens = finalizeTokens(adaptTokens(input.transport, usage, meta));
  return {
    tokens,
    evidence: extractEvidence(input, meta),
  };
}

function adaptTokens(
  transport: AttemptTransport,
  usage: Record<string, unknown> | undefined,
  meta: Record<string, unknown> | undefined,
): AttemptTokens {
  switch (transport) {
    case "anthropic-messages":
      return adaptAnthropicMessages(usage, meta);
    case "bedrock-converse":
      return adaptBedrockConverse(usage, meta);
    case "pensar-anthropic-stream":
      return adaptPensarAnthropicStream(usage);
    case "pensar-anthropic-rest":
      return adaptPensarAnthropicRest(usage);
    case "openai-responses":
      return adaptOpenAIResponses(usage);
    case "sdk-normalized":
      return adaptSdkNormalized(usage, meta);
  }
}

function adaptAnthropicMessages(
  usage: Record<string, unknown> | undefined,
  meta: Record<string, unknown> | undefined,
): AttemptTokens {
  const anthropicMeta = asRecord(meta?.anthropic, "providerMetadata.anthropic");
  const uncachedInput = firstToken(usage, ["input_tokens", "inputTokens"]);
  const cacheRead = firstToken(usage, [
    "cache_read_input_tokens",
    "cacheReadInputTokens",
  ]);
  const cacheWrite = firstToken(usage, [
    "cache_creation_input_tokens",
    "cacheCreationInputTokens",
  ]);
  const output = firstToken(usage, ["output_tokens", "outputTokens"]);

  return {
    inclusiveInput: null,
    uncachedInput: uncachedInput ?? firstToken(anthropicMeta, ["inputTokens"]),
    cacheRead: cacheRead ?? firstToken(anthropicMeta, ["cacheReadInputTokens"]),
    cacheWrite:
      cacheWrite ?? firstToken(anthropicMeta, ["cacheCreationInputTokens"]),
    output: output ?? firstToken(anthropicMeta, ["outputTokens"]),
  };
}

function adaptBedrockConverse(
  usage: Record<string, unknown> | undefined,
  meta: Record<string, unknown> | undefined,
): AttemptTokens {
  const bedrockMeta = asRecord(meta?.bedrock, "providerMetadata.bedrock");
  const bedrockUsage = asRecord(
    bedrockMeta?.usage,
    "providerMetadata.bedrock.usage",
  );
  const anthropicMeta = asRecord(meta?.anthropic, "providerMetadata.anthropic");

  // Raw Bedrock usage reports uncached inputTokens plus cache* keys.
  if (
    usage &&
    (hasOwn(usage, "cacheReadInputTokens") ||
      hasOwn(usage, "cacheWriteInputTokens"))
  ) {
    return {
      inclusiveInput: null,
      uncachedInput: readToken(usage, "inputTokens"),
      cacheRead: firstToken({ ...bedrockUsage, ...usage }, [
        "cacheReadInputTokens",
      ]),
      cacheWrite: firstToken({ ...bedrockUsage, ...usage }, [
        "cacheWriteInputTokens",
      ]),
      output: readToken(usage, "outputTokens"),
    };
  }

  const sdk = readSdkOrV3Usage(usage);
  const cacheRead = firstPresent(
    firstToken(bedrockUsage, ["cacheReadInputTokens"]),
    firstToken(bedrockMeta, ["cacheReadInputTokens"]),
    firstToken(anthropicMeta, ["cacheReadInputTokens"]),
    sdk.cacheRead,
  );
  const cacheWrite = firstPresent(
    firstToken(bedrockUsage, ["cacheWriteInputTokens"]),
    firstToken(bedrockMeta, ["cacheWriteInputTokens"]),
    firstToken(anthropicMeta, [
      "cacheWriteInputTokens",
      "cacheCreationInputTokens",
    ]),
    sdk.cacheWrite,
  );

  return {
    inclusiveInput: sdk.inclusive,
    uncachedInput: sdk.uncached,
    cacheRead,
    cacheWrite,
    output: sdk.output,
  };
}

function adaptPensarAnthropicStream(
  usage: Record<string, unknown> | undefined,
): AttemptTokens {
  const sdk = readSdkOrV3Usage(usage);
  return {
    inclusiveInput: sdk.inclusive,
    uncachedInput: sdk.uncached,
    cacheRead: sdk.cacheRead,
    cacheWrite: sdk.cacheWrite,
    output: sdk.output,
  };
}

function adaptPensarAnthropicRest(
  usage: Record<string, unknown> | undefined,
): AttemptTokens {
  const nativeUncached = firstToken(usage, ["input_tokens"]);
  if (nativeUncached !== null) {
    return {
      inclusiveInput: null,
      uncachedInput: nativeUncached,
      cacheRead: firstToken(usage, ["cache_read_input_tokens"]),
      cacheWrite: firstToken(usage, ["cache_creation_input_tokens"]),
      output: firstToken(usage, ["output_tokens"]),
    };
  }

  const sdk = readSdkOrV3Usage(usage);
  // parseAnthropicResponse copies native input_tokens into total and
  // leaves cache / noCache undefined — total is uncached, not inclusive.
  return {
    inclusiveInput: null,
    uncachedInput: sdk.inclusive,
    cacheRead: null,
    cacheWrite: null,
    output: sdk.output,
  };
}

function adaptOpenAIResponses(
  usage: Record<string, unknown> | undefined,
): AttemptTokens {
  const details = asRecord(usage?.input_tokens_details, "input_tokens_details");
  const nativeInclusive = firstToken(usage, ["input_tokens"]);
  if (nativeInclusive !== null || details) {
    return {
      inclusiveInput: nativeInclusive,
      uncachedInput: null,
      cacheRead: firstToken(details, ["cached_tokens"]),
      cacheWrite: 0,
      output: firstToken(usage, ["output_tokens"]),
    };
  }

  const sdk = readSdkOrV3Usage(usage);
  return {
    inclusiveInput: sdk.inclusive,
    uncachedInput: sdk.uncached,
    cacheRead: sdk.cacheRead,
    cacheWrite: 0,
    output: sdk.output,
  };
}

function adaptSdkNormalized(
  usage: Record<string, unknown> | undefined,
  meta: Record<string, unknown> | undefined,
): AttemptTokens {
  const sdk = readSdkOrV3Usage(usage);
  const anthropicMeta = asRecord(meta?.anthropic, "providerMetadata.anthropic");
  return {
    inclusiveInput: sdk.inclusive,
    uncachedInput: sdk.uncached,
    cacheRead:
      firstToken(anthropicMeta, ["cacheReadInputTokens"]) ?? sdk.cacheRead,
    cacheWrite:
      firstToken(anthropicMeta, ["cacheCreationInputTokens"]) ?? sdk.cacheWrite,
    output: sdk.output,
  };
}

function readSdkOrV3Usage(usage: Record<string, unknown> | undefined): {
  inclusive: number | null;
  uncached: number | null;
  cacheRead: number | null;
  cacheWrite: number | null;
  output: number | null;
} {
  if (!usage) {
    return {
      inclusive: null,
      uncached: null,
      cacheRead: null,
      cacheWrite: null,
      output: null,
    };
  }

  if (isRecord(usage.inputTokens)) {
    const nested = usage.inputTokens;
    const outputNested = isRecord(usage.outputTokens)
      ? usage.outputTokens
      : undefined;
    return {
      inclusive: readToken(nested, "total"),
      uncached: readToken(nested, "noCache"),
      cacheRead: readToken(nested, "cacheRead"),
      cacheWrite: readToken(nested, "cacheWrite"),
      output: outputNested
        ? readToken(outputNested, "total")
        : readToken(usage, "outputTokens"),
    };
  }

  const details = asRecord(usage.inputTokenDetails, "inputTokenDetails");
  return {
    inclusive: readToken(usage, "inputTokens"),
    uncached: firstToken(details, ["noCacheTokens", "noCache"]),
    cacheRead: firstToken(details, ["cacheReadTokens", "cacheRead"]),
    cacheWrite: firstToken(details, ["cacheWriteTokens", "cacheWrite"]),
    output: readToken(usage, "outputTokens"),
  };
}

function extractEvidence(
  input: TransportUsageInput,
  meta: Record<string, unknown> | undefined,
): AttemptEvidence {
  const evidence: AttemptEvidence = {};
  const anthropicMeta = asRecord(meta?.anthropic, "providerMetadata.anthropic");
  const bedrockMeta = asRecord(meta?.bedrock, "providerMetadata.bedrock");
  const bedrockMetadata = asRecord(
    bedrockMeta?.$metadata,
    "providerMetadata.bedrock.$metadata",
  );
  const openaiMeta = asRecord(meta?.openai, "providerMetadata.openai");

  const providerRequestId =
    readNonEmptyString(input.providerRequestId, "providerRequestId") ??
    firstString(anthropicMeta, ["id", "messageId", "requestId"]) ??
    firstString(bedrockMeta, ["requestId"]) ??
    firstString(bedrockMetadata, ["requestId"]) ??
    firstString(openaiMeta, ["id", "responseId", "requestId"]);
  if (providerRequestId) {
    evidence.providerRequestId = providerRequestId;
  }

  if (input.cacheTtlSeconds !== undefined) {
    const ttl = parseTokenCount(input.cacheTtlSeconds, "cacheTtlSeconds");
    if (ttl !== null) {
      evidence.cacheTtlSeconds = ttl;
    }
  }

  if (input.cacheBreakpoint) {
    if (!CACHE_BREAKPOINTS.includes(input.cacheBreakpoint)) {
      throw new InferenceAttemptValidationError(
        "invalid-envelope",
        `unknown cacheBreakpoint ${String(input.cacheBreakpoint)}`,
      );
    }
    evidence.cacheBreakpoint = input.cacheBreakpoint;
  }

  return evidence;
}

function asRecord(
  value: unknown,
  label: string,
): Record<string, unknown> | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new InferenceAttemptValidationError(
      "invalid-token",
      `${label} must be an object`,
    );
  }
  return value as Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(obj: Record<string, unknown>, key: string): boolean {
  return Object.hasOwn(obj, key);
}

function readToken(
  obj: Record<string, unknown> | undefined,
  key: string,
): number | null {
  if (!obj || !hasOwn(obj, key)) {
    return null;
  }
  return parseTokenCount(obj[key], key);
}

function firstToken(
  obj: Record<string, unknown> | undefined,
  keys: string[],
): number | null {
  if (!obj) {
    return null;
  }
  for (const key of keys) {
    if (hasOwn(obj, key)) {
      return parseTokenCount(obj[key], key);
    }
  }
  return null;
}

function firstPresent(...values: Array<number | null>): number | null {
  for (const value of values) {
    if (value !== null) {
      return value;
    }
  }
  return null;
}

function firstString(
  obj: Record<string, unknown> | undefined,
  keys: string[],
): string | undefined {
  if (!obj) {
    return undefined;
  }
  for (const key of keys) {
    if (hasOwn(obj, key)) {
      return readNonEmptyString(obj[key], key);
    }
  }
  return undefined;
}

function readNonEmptyString(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new InferenceAttemptValidationError(
      "invalid-envelope",
      `${label} must be a non-empty string`,
    );
  }
  return value;
}

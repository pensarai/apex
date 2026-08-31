import { ProviderAttemptValidationError } from "./errors";

/** Known token count, or `null` when the provider did not report the field. */
export type MaybeTokenCount = number | null;

export const UNKNOWN_TOKEN_COUNT: MaybeTokenCount = null;

export interface AttemptTokens {
  inclusiveInput: MaybeTokenCount;
  uncachedInput: MaybeTokenCount;
  cacheRead: MaybeTokenCount;
  cacheWrite: MaybeTokenCount;
  output: MaybeTokenCount;
}

export const UNKNOWN_TOKENS: AttemptTokens = {
  inclusiveInput: null,
  uncachedInput: null,
  cacheRead: null,
  cacheWrite: null,
  output: null,
};

export function parseTokenCount(
  value: unknown,
  label: string,
): MaybeTokenCount {
  if (value === undefined || value === null) {
    return null;
  }
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 0 ||
    !Number.isFinite(value)
  ) {
    throw new ProviderAttemptValidationError(
      "invalid-token",
      `${label} must be a finite non-negative integer or null`,
    );
  }
  return value;
}

/**
 * Close the input identity when exactly one of the four input fields is
 * unknown. Does not invent values when two or more fields are missing.
 */
function deriveInputTokens(tokens: AttemptTokens): AttemptTokens {
  const { inclusiveInput, uncachedInput, cacheRead, cacheWrite, output } =
    tokens;
  const unknownCount = [
    inclusiveInput,
    uncachedInput,
    cacheRead,
    cacheWrite,
  ].filter((value) => value === null).length;
  if (unknownCount !== 1) {
    return tokens;
  }

  const derived: AttemptTokens = {
    inclusiveInput,
    uncachedInput,
    cacheRead,
    cacheWrite,
    output,
  };

  if (
    inclusiveInput === null &&
    uncachedInput !== null &&
    cacheRead !== null &&
    cacheWrite !== null
  ) {
    derived.inclusiveInput = uncachedInput + cacheRead + cacheWrite;
  } else if (
    uncachedInput === null &&
    inclusiveInput !== null &&
    cacheRead !== null &&
    cacheWrite !== null
  ) {
    derived.uncachedInput = inclusiveInput - cacheRead - cacheWrite;
  } else if (
    cacheRead === null &&
    inclusiveInput !== null &&
    uncachedInput !== null &&
    cacheWrite !== null
  ) {
    derived.cacheRead = inclusiveInput - uncachedInput - cacheWrite;
  } else if (
    cacheWrite === null &&
    inclusiveInput !== null &&
    uncachedInput !== null &&
    cacheRead !== null
  ) {
    derived.cacheWrite = inclusiveInput - uncachedInput - cacheRead;
  }

  for (const [label, value] of [
    ["inclusiveInput", derived.inclusiveInput],
    ["uncachedInput", derived.uncachedInput],
    ["cacheRead", derived.cacheRead],
    ["cacheWrite", derived.cacheWrite],
  ] as const) {
    if (value !== null && value < 0) {
      throw new ProviderAttemptValidationError(
        "inclusive-identity",
        `derived ${label} is negative (${value})`,
      );
    }
  }

  return derived;
}

function assertTokenIdentity(tokens: AttemptTokens): void {
  const { inclusiveInput, uncachedInput, cacheRead, cacheWrite } = tokens;

  if (
    inclusiveInput !== null &&
    uncachedInput !== null &&
    cacheRead !== null &&
    cacheWrite !== null
  ) {
    if (inclusiveInput !== uncachedInput + cacheRead + cacheWrite) {
      throw new ProviderAttemptValidationError(
        "inclusive-identity",
        `inclusive input ${inclusiveInput} !== uncached ${uncachedInput} + cacheRead ${cacheRead} + cacheWrite ${cacheWrite}`,
      );
    }
    return;
  }

  if (inclusiveInput === null) {
    return;
  }

  for (const [label, value] of [
    ["uncachedInput", uncachedInput],
    ["cacheRead", cacheRead],
    ["cacheWrite", cacheWrite],
  ] as const) {
    if (value !== null && value > inclusiveInput) {
      throw new ProviderAttemptValidationError(
        "inclusive-identity",
        `${label} ${value} exceeds inclusive input ${inclusiveInput}`,
      );
    }
  }

  const knownSum = (uncachedInput ?? 0) + (cacheRead ?? 0) + (cacheWrite ?? 0);
  if (knownSum > inclusiveInput) {
    throw new ProviderAttemptValidationError(
      "inclusive-identity",
      `known input components ${knownSum} exceed inclusive input ${inclusiveInput}`,
    );
  }
}

export function finalizeTokens(tokens: AttemptTokens): AttemptTokens {
  const derived = deriveInputTokens(tokens);
  assertTokenIdentity(derived);
  return derived;
}

import type { ProviderAttemptEnvelope } from "./envelope";
import { assertLineage, ProviderAttemptEnvelopeSchema } from "./envelope";
import { ProviderAttemptValidationError } from "./errors";
import { finalizeTokens } from "./tokens";

export function parseProviderAttemptEnvelope(
  value: unknown,
): ProviderAttemptEnvelope {
  const parsed = ProviderAttemptEnvelopeSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path.length ? issue.path.join(".") : "envelope";
    throw new ProviderAttemptValidationError(
      "invalid-envelope",
      `${path}: ${issue?.message ?? "invalid envelope"}`,
    );
  }

  assertLineage(parsed.data.lineage);
  const tokens = finalizeTokens(parsed.data.tokens);
  return { ...parsed.data, tokens };
}

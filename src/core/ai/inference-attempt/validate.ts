import type { InferenceAttempt } from "./envelope";
import { assertLineage, InferenceAttemptSchema } from "./envelope";
import { InferenceAttemptValidationError } from "./errors";
import { finalizeTokens } from "./tokens";

export function parseInferenceAttempt(value: unknown): InferenceAttempt {
  const parsed = InferenceAttemptSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path.length ? issue.path.join(".") : "envelope";
    throw new InferenceAttemptValidationError(
      "invalid-envelope",
      `${path}: ${issue?.message ?? "invalid envelope"}`,
    );
  }

  assertLineage(parsed.data.lineage);
  const tokens = finalizeTokens(parsed.data.tokens);
  return { ...parsed.data, tokens };
}

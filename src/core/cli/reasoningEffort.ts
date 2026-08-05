import type { OpenAIReasoningEffort } from "../ai";

const REASONING_EFFORTS = new Set<OpenAIReasoningEffort>([
  "none",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
  "ultra",
]);

export function parseReasoningEffort(
  value: string | undefined,
): OpenAIReasoningEffort | undefined {
  if (value === undefined) return undefined;
  if (!REASONING_EFFORTS.has(value as OpenAIReasoningEffort)) {
    throw new Error(
      "--reasoning-effort must be one of: none, low, medium, high, xhigh, max, ultra",
    );
  }
  return value as OpenAIReasoningEffort;
}

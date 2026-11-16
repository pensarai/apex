// The mantle: prefix distinguishes OpenAI Responses routes from Bedrock Converse.

const MANTLE_PREFIX = "mantle:";

const MANTLE_GPT_5_5_MODEL_ID = "openai.gpt-5.5";

export const MANTLE_GPT_5_5_ROUTED_ID = `${MANTLE_PREFIX}${MANTLE_GPT_5_5_MODEL_ID}`;

// Preserve the original GPT 5.5 default for callers building a URL directly.
export const MANTLE_REGION = process.env.BEDROCK_MANTLE_REGION || "us-east-2";

export function mantleRegion(modelId: string): string {
  // GPT 6.1 Sol is available on Mantle in us-east-1; AWS_REGION is not model availability.
  return (
    process.env.BEDROCK_MANTLE_REGION ||
    (stripMantlePrefix(modelId) === "openai.gpt-6.1-sol"
      ? "us-east-1"
      : "us-east-2")
  );
}

export function stripMantlePrefix(modelId: string): string {
  return modelId.startsWith(MANTLE_PREFIX)
    ? modelId.slice(MANTLE_PREFIX.length)
    : modelId;
}

/** Whether the gateway uses OpenAI Responses formatting for this Bedrock ID. */
export function isMantleResponsesModelId(modelId: string): boolean {
  const native = stripMantlePrefix(modelId);
  return /^openai\.gpt-5/.test(native) || native === "openai.gpt-6.1-sol";
}

/**
 * Mantle OpenAI base URL. The Responses model appends `/responses`, yielding
 * `https://bedrock-mantle.{region}.api.aws/openai/v1/responses` — note the
 * `openai/` segment, which differs from the gpt-oss `/v1` chat path.
 */
export function mantleBaseUrl(region: string = MANTLE_REGION): string {
  return `https://bedrock-mantle.${region}.api.aws/openai/v1`;
}

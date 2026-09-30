// Mantle uses the OpenAI Responses API; model availability is region-specific.

const MANTLE_PREFIX = "mantle:";

const MANTLE_GPT_5_5_MODEL_ID = "openai.gpt-5.5";

export const MANTLE_GPT_5_5_ROUTED_ID = `${MANTLE_PREFIX}${MANTLE_GPT_5_5_MODEL_ID}`;

/**
 * GPT 5.5 is GA only in us-east-2. Override with BEDROCK_MANTLE_REGION if AWS
 * widens availability; never fall back to the app's default AWS_REGION.
 */
export const MANTLE_REGION = process.env.BEDROCK_MANTLE_REGION || "us-east-2";

const MANTLE_MODEL_REGIONS: Record<string, string> = {
  "openai.gpt-6-astra": "us-west-2",
};

export function getMantleRegion(modelId: string): string {
  return (
    process.env.BEDROCK_MANTLE_REGION ||
    MANTLE_MODEL_REGIONS[stripMantlePrefix(modelId)] ||
    MANTLE_REGION
  );
}

export function stripMantlePrefix(modelId: string): string {
  return modelId.startsWith(MANTLE_PREFIX)
    ? modelId.slice(MANTLE_PREFIX.length)
    : modelId;
}

/**
 * Whether a (de-prefixed) Bedrock model ID must go through the Mantle OpenAI
 * Responses API. Scoped to the GPT-5.x family that is Responses-API-only.
 */
export function isMantleResponsesModelId(modelId: string): boolean {
  return /^openai\.gpt-5/.test(stripMantlePrefix(modelId));
}

/**
 * Mantle OpenAI base URL. The Responses model appends `/responses`, yielding
 * `https://bedrock-mantle.{region}.api.aws/openai/v1/responses` — note the
 * `openai/` segment, which differs from the gpt-oss `/v1` chat path.
 */
export function mantleBaseUrl(region: string = MANTLE_REGION): string {
  return `https://bedrock-mantle.${region}.api.aws/openai/v1`;
}

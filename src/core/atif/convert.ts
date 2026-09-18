import { createHash } from "node:crypto";
import {
  type EvidenceAvailability,
  type JsonValue,
  type NativeRolloutEvidenceEnvelopeV1,
  parseNativeRolloutEvidence,
  stringifyCanonicalJson,
} from "../ai/native-rollout-evidence";
import type {
  AtifAgent,
  AtifContentPart,
  AtifDiagnostic,
  AtifMetrics,
  AtifObservationResult,
  AtifStep,
  AtifToolCall,
  AtifToolDefinition,
  AtifTrajectoryV1_8,
  ConvertNativeRolloutToAtifInput,
  JsonObject,
  ParsedNativeRolloutSource,
} from "./schema";
import { ATIF_EXPORT_SOURCE_LIMITS, ATIF_SCHEMA_VERSION } from "./schema";

const SOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PORTABLE_ATTEMPT_ID_PATTERN = /^atm_[A-Za-z0-9_-]{1,128}$/;
const IMAGE_MEDIA_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
]);
const AUDIO_MEDIA_TYPES = new Set([
  "audio/wav",
  "audio/mpeg",
  "audio/mp4",
  "audio/aac",
  "audio/ogg",
  "audio/flac",
  "audio/webm",
  "audio/aiff",
]);
const AUDIO_MEDIA_ALIASES: Record<string, string> = {
  "audio/mp3": "audio/mpeg",
  "audio/mpga": "audio/mpeg",
  "audio/x-mpeg": "audio/mpeg",
  "audio/x-wav": "audio/wav",
  "audio/wave": "audio/wav",
  "audio/vnd.wave": "audio/wav",
  "audio/x-m4a": "audio/mp4",
  "audio/m4a": "audio/mp4",
  "audio/x-aac": "audio/aac",
  "audio/x-flac": "audio/flac",
  "audio/x-aiff": "audio/aiff",
};

interface DraftFile {
  kind: "asset" | "source";
  path: string;
  mediaType: string;
  bytes: Uint8Array;
  required?: boolean;
}

export interface AtifConversionDraft {
  rootTrajectoryId: string;
  exporter: ConvertNativeRolloutToAtifInput["exporter"];
  documents: Readonly<Record<string, readonly AtifTrajectoryV1_8[]>>;
  documentPaths: ReadonlyMap<string, string>;
  files: readonly DraftFile[];
  diagnostics: AtifDiagnostic[];
  nativeSampling: NativeSamplingSummary;
  independentValidation?: ConvertNativeRolloutToAtifInput["independentValidation"];
}

type AvailabilityState =
  | "available"
  | "unsupported"
  | "omitted"
  | "truncated"
  | "interrupted";

type AvailabilityCounts = Record<AvailabilityState, number>;

export type NativeSamplingSummary = Record<
  "promptTokenIds" | "completionTokenIds" | "logprobs" | "tokenizer" | "extra",
  AvailabilityCounts
>;

interface AssetCollector {
  files: Map<string, DraftFile>;
  addJson(
    sha256: string,
    mediaType: string,
    content: JsonValue,
    sourceId: string,
  ): void;
  addBinary(bytes: Uint8Array, mediaType: string, sourceId: string): string;
}

interface ConversionContext {
  source: ParsedNativeRolloutSource;
  assets: AssetCollector;
  diagnostics: AtifDiagnostic[];
}

interface StepContent {
  messageParts: AtifContentPart[];
  reasoning: string[];
  toolCalls: AtifToolCall[];
  observations: AtifObservationResult[];
  extra: JsonObject;
}

export class AtifConversionError extends Error {
  readonly diagnostics: AtifDiagnostic[];

  constructor(message: string, diagnostics: AtifDiagnostic[]) {
    super(message);
    this.name = "AtifConversionError";
    this.diagnostics = diagnostics;
  }
}

function asObject(value: unknown): JsonObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asArray(value: unknown): JsonValue[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function hashBytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function diagnostic(
  diagnostics: AtifDiagnostic[],
  sourceId: string,
  code: string,
  message: string,
  path?: string,
  severity: "error" | "warning" = "warning",
): void {
  diagnostics.push({
    code,
    severity,
    message,
    sourceId,
    ...(path ? { path } : {}),
  });
}

function parseSources(
  sources: ConvertNativeRolloutToAtifInput["sources"],
): ParsedNativeRolloutSource[] {
  if (sources.length > ATIF_EXPORT_SOURCE_LIMITS.maxSources) {
    throw new AtifConversionError("recorded evidence source limit exceeded", [
      {
        code: "source_count_limit",
        severity: "error",
        message: `a bundle accepts at most ${ATIF_EXPORT_SOURCE_LIMITS.maxSources} sources`,
      },
    ]);
  }
  const totalSourceBytes = sources.reduce(
    (total, source) => total + source.bytes.byteLength,
    0,
  );
  if (totalSourceBytes > ATIF_EXPORT_SOURCE_LIMITS.maxTotalSourceBytes) {
    throw new AtifConversionError("recorded evidence byte limit exceeded", [
      {
        code: "source_byte_limit",
        severity: "error",
        message: `bundle source bytes exceed ${ATIF_EXPORT_SOURCE_LIMITS.maxTotalSourceBytes}`,
      },
    ]);
  }
  const diagnostics: AtifDiagnostic[] = [];
  const ids = new Set<string>();
  const parsed: ParsedNativeRolloutSource[] = [];
  for (const source of sources) {
    if (!SOURCE_ID_PATTERN.test(source.id)) {
      diagnostic(
        diagnostics,
        source.id || "source",
        "invalid_source_id",
        "source id must be a portable filename component",
        "source.id",
        "error",
      );
      continue;
    }
    if (ids.has(source.id)) {
      diagnostic(
        diagnostics,
        source.id,
        "duplicate_source_id",
        "source id appears more than once",
        "source.id",
        "error",
      );
      continue;
    }
    ids.add(source.id);
    const measuredHash = hashBytes(source.bytes);
    if (
      measuredHash !== source.sha256 ||
      source.bytes.byteLength !== source.sizeBytes
    ) {
      diagnostic(
        diagnostics,
        source.id,
        "source_identity_mismatch",
        "source bytes do not match the supplied immutable identity",
        "source",
        "error",
      );
      continue;
    }
    try {
      const raw = JSON.parse(Buffer.from(source.bytes).toString("utf8"));
      const evidence = parseNativeRolloutEvidence(raw);
      if (!PORTABLE_ATTEMPT_ID_PATTERN.test(evidence.attempt.attemptId)) {
        diagnostic(
          diagnostics,
          source.id,
          "invalid_attempt_path_identity",
          "attemptId cannot be represented as a portable trajectory path",
          "attempt.attemptId",
          "error",
        );
        continue;
      }
      parsed.push({ ...source, evidence });
    } catch (error) {
      diagnostic(
        diagnostics,
        source.id,
        "invalid_source",
        error instanceof Error
          ? error.message
          : "source is not valid JSON evidence",
        "source",
        "error",
      );
    }
  }
  if (diagnostics.length > 0) {
    throw new AtifConversionError(
      "recorded evidence source validation failed",
      diagnostics,
    );
  }
  if (parsed.length === 0) {
    throw new AtifConversionError(
      "at least one recorded evidence source is required",
      [
        {
          code: "missing_source",
          severity: "error",
          message: "at least one recorded evidence source is required",
        },
      ],
    );
  }
  const runIds = new Set(parsed.map((source) => source.evidence.runId));
  if (runIds.size !== 1) {
    throw new AtifConversionError("a bundle cannot mix runs", [
      {
        code: "mixed_run_sources",
        severity: "error",
        message: "all evidence sources in a bundle must have the same runId",
      },
    ]);
  }
  return parsed;
}

function createAssetCollector(diagnostics: AtifDiagnostic[]): AssetCollector {
  const files = new Map<string, DraftFile>();
  const add = (file: DraftFile, sourceId: string) => {
    const existing = files.get(file.path);
    if (
      existing &&
      (hashBytes(existing.bytes) !== hashBytes(file.bytes) ||
        existing.mediaType !== file.mediaType)
    ) {
      diagnostic(
        diagnostics,
        sourceId,
        "asset_identity_conflict",
        `asset path ${file.path} resolved to conflicting content`,
        file.path,
        "error",
      );
      return;
    }
    files.set(file.path, file);
  };
  return {
    files,
    addJson(sha256, mediaType, content, sourceId) {
      const bytes = Buffer.from(stringifyCanonicalJson(content));
      const path = `assets/${sha256}.json`;
      if (hashBytes(bytes) !== sha256) {
        diagnostic(
          diagnostics,
          sourceId,
          "asset_hash_mismatch",
          "evidence asset content does not match its source hash",
          path,
          "error",
        );
        return;
      }
      add({ kind: "asset", path, mediaType, bytes, required: true }, sourceId);
    },
    addBinary(bytes, mediaType, sourceId) {
      const sha256 = hashBytes(bytes);
      const path = `assets/${sha256}`;
      add({ kind: "asset", path, mediaType, bytes, required: true }, sourceId);
      return path;
    },
  };
}

function canonicalAudioMediaType(mediaType: string): string {
  return AUDIO_MEDIA_ALIASES[mediaType] ?? mediaType;
}

function decodeBase64(value: string): Uint8Array | undefined {
  const compact = value.replace(/\s/g, "");
  if (compact.length === 0 || compact.length % 4 !== 0) return undefined;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) return undefined;
  const bytes = Buffer.from(compact, "base64");
  const roundTrip = bytes.toString("base64").replace(/=+$/, "");
  return roundTrip === compact.replace(/=+$/, "") ? bytes : undefined;
}

function contentPartFromFile(
  value: JsonObject,
  context: ConversionContext,
  path: string,
): AtifContentPart | undefined {
  const originalMediaType = value.mediaType;
  if (typeof originalMediaType !== "string") {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "missing_media_type",
      "file content has no media type",
      path,
    );
    return undefined;
  }
  const mediaType = canonicalAudioMediaType(originalMediaType);
  const type = IMAGE_MEDIA_TYPES.has(mediaType)
    ? "image"
    : AUDIO_MEDIA_TYPES.has(mediaType)
      ? "audio"
      : undefined;
  if (!type) {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "unsupported_media_type",
      `ATIF-v1.8 cannot represent ${originalMediaType} as message content`,
      path,
    );
    return undefined;
  }

  const data = value.data;
  const tagged = asObject(data);
  let assetPath: string | undefined;
  if (tagged?.$type === "url" && typeof tagged.value === "string") {
    try {
      const url = new URL(tagged.value);
      if (url.protocol !== "https:" && url.protocol !== "http:") {
        throw new Error("unsupported URL protocol");
      }
      assetPath = url.toString();
      diagnostic(
        context.diagnostics,
        context.source.id,
        "external_asset_not_archived",
        "multimodal content references an external URL whose bytes are not archived in this bundle",
        path,
      );
    } catch {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "invalid_media_url",
        "file content has a non-portable or invalid URL",
        path,
      );
      return undefined;
    }
  } else {
    const encoded =
      typeof data === "string"
        ? data
        : tagged?.$type === "bytes" && typeof tagged.value === "string"
          ? tagged.value
          : undefined;
    const bytes = encoded === undefined ? undefined : decodeBase64(encoded);
    if (!bytes) {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "invalid_media_data",
        "file content is neither a preserved URL nor valid base64 bytes",
        path,
      );
      return undefined;
    }
    assetPath = context.assets.addBinary(bytes, mediaType, context.source.id);
  }
  return type === "image"
    ? {
        type,
        source: {
          media_type: mediaType as
            | "image/jpeg"
            | "image/png"
            | "image/gif"
            | "image/webp",
          path: assetPath,
        },
      }
    : {
        type,
        source: {
          media_type: mediaType as
            | "audio/wav"
            | "audio/mpeg"
            | "audio/mp4"
            | "audio/aac"
            | "audio/ogg"
            | "audio/flac"
            | "audio/webm"
            | "audio/aiff",
          path: assetPath,
        },
      };
}

function emptyStepContent(): StepContent {
  return {
    messageParts: [],
    reasoning: [],
    toolCalls: [],
    observations: [],
    extra: {},
  };
}

function parseToolArguments(
  value: JsonValue | undefined,
  context: ConversionContext,
  path: string,
): JsonObject | undefined {
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      const object = asObject(parsed);
      if (object) return object;
    } catch {
      // The diagnostic below preserves one failure shape for invalid or non-object JSON.
    }
  } else {
    const object = asObject(value);
    if (object) return object;
  }
  diagnostic(
    context.diagnostics,
    context.source.id,
    "invalid_tool_arguments",
    "tool arguments are not a JSON object and were not exported as a call",
    path,
  );
  return undefined;
}

function toolCallFromPart(
  part: JsonObject,
  context: ConversionContext,
  path: string,
): AtifToolCall | undefined {
  const id = part.toolCallId;
  const name = part.toolName;
  if (typeof id !== "string" || typeof name !== "string") {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "invalid_tool_call",
      "tool call is missing its stable id or function name",
      path,
    );
    return undefined;
  }
  const args = parseToolArguments(part.input, context, `${path}.input`);
  if (!args) return undefined;
  const extra: JsonObject = {};
  if (typeof part.providerExecuted === "boolean") {
    extra.provider_executed = part.providerExecuted;
  }
  if (typeof part.dynamic === "boolean") extra.dynamic = part.dynamic;
  return {
    tool_call_id: id,
    function_name: name,
    arguments: args,
    ...(Object.keys(extra).length > 0 ? { extra } : {}),
  };
}

function toolResultContent(output: JsonValue | undefined): string {
  const result = asObject(output);
  if (!result) return stringifyCanonicalJson(output ?? null);
  if (
    (result.type === "text" || result.type === "error-text") &&
    typeof result.value === "string"
  ) {
    return result.value;
  }
  if (result.type === "execution-denied") {
    return typeof result.reason === "string"
      ? result.reason
      : "Tool execution was denied.";
  }
  if (result.type === "json" || result.type === "error-json") {
    return stringifyCanonicalJson(result.value ?? null);
  }
  return stringifyCanonicalJson(result);
}

function toolResultFromPart(
  part: JsonObject,
  context: ConversionContext,
  path: string,
): AtifObservationResult | undefined {
  if (typeof part.toolCallId !== "string") {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "invalid_tool_result",
      "tool result is missing source call identity",
      path,
    );
    return undefined;
  }
  const content =
    part.output !== undefined
      ? toolResultContent(part.output)
      : part.result !== undefined
        ? stringifyCanonicalJson(part.result)
        : "";
  const extra: JsonObject = {};
  if (typeof part.toolName === "string") extra.tool_name = part.toolName;
  if (typeof part.isError === "boolean") extra.is_error = part.isError;
  if (typeof part.preliminary === "boolean") {
    extra.preliminary = part.preliminary;
  }
  return {
    source_call_id: part.toolCallId,
    content,
    ...(Object.keys(extra).length > 0 ? { extra } : {}),
  };
}

function collectParts(
  parts: JsonValue[],
  context: ConversionContext,
  path: string,
): StepContent {
  const content = emptyStepContent();
  for (const [index, raw] of parts.entries()) {
    const part = asObject(raw);
    const partPath = `${path}[${index}]`;
    if (!part || typeof part.type !== "string") {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "invalid_content_part",
        "content part is not a typed object",
        partPath,
      );
      continue;
    }
    if (part.type === "text" && typeof part.text === "string") {
      content.messageParts.push({ type: "text", text: part.text });
    } else if (part.type === "reasoning" && typeof part.text === "string") {
      content.reasoning.push(part.text);
    } else if (part.type === "file") {
      const converted = contentPartFromFile(part, context, partPath);
      if (converted) content.messageParts.push(converted);
    } else if (part.type === "tool-call") {
      const call = toolCallFromPart(part, context, partPath);
      if (call) content.toolCalls.push(call);
    } else if (part.type === "tool-result") {
      const result = toolResultFromPart(part, context, partPath);
      if (result) content.observations.push(result);
    } else if (part.type === "source") {
      const sources = (content.extra.sources as JsonValue[] | undefined) ?? [];
      sources.push(part);
      content.extra.sources = sources;
    } else {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "unsupported_content_part",
        `content part ${part.type} is retained only in source evidence`,
        partPath,
      );
    }
  }
  return content;
}

function messageFromParts(
  parts: AtifContentPart[],
): string | AtifContentPart[] {
  if (parts.length === 0) return "";
  if (parts.length === 1 && parts[0]?.type === "text") return parts[0].text;
  return parts;
}

function makeStep(
  stepId: number,
  source: "system" | "user" | "agent",
  content: StepContent,
  input: {
    copied: boolean;
    modelName?: string;
    metrics?: AtifMetrics;
    extra?: JsonObject;
  },
): AtifStep {
  const extra = { ...content.extra, ...(input.extra ?? {}) };
  return {
    step_id: stepId,
    source,
    message: messageFromParts(content.messageParts),
    ...(source === "agent" && input.modelName
      ? { model_name: input.modelName }
      : {}),
    ...(content.reasoning.length > 0
      ? { reasoning_content: content.reasoning.join("") }
      : {}),
    ...(content.toolCalls.length > 0 ? { tool_calls: content.toolCalls } : {}),
    ...(content.observations.length > 0
      ? { observation: { results: content.observations } }
      : {}),
    ...(input.metrics ? { metrics: input.metrics } : {}),
    ...(Object.keys(extra).length > 0 ? { extra } : {}),
    ...(source === "agent" && !input.copied ? { llm_call_count: 1 } : {}),
    ...(input.copied ? { is_copied_context: true } : {}),
  };
}

function promptSteps(
  prompt: JsonValue[] | undefined,
  context: ConversionContext,
): AtifStep[] {
  if (!prompt) {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "missing_prompt",
      "normalized evidence has no prompt array",
      "boundary.input.normalizedRef",
    );
    return [];
  }
  const steps: AtifStep[] = [];
  for (const [index, raw] of prompt.entries()) {
    const message = asObject(raw);
    const path = `prompt[${index}]`;
    if (!message || typeof message.role !== "string") {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "invalid_prompt_message",
        "prompt message has no supported role",
        path,
      );
      continue;
    }
    if (message.role === "system" && typeof message.content === "string") {
      steps.push(
        makeStep(
          steps.length + 1,
          "system",
          {
            ...emptyStepContent(),
            messageParts: [{ type: "text", text: message.content }],
          },
          { copied: true },
        ),
      );
      continue;
    }
    const parts = asArray(message.content);
    if (!parts) {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "invalid_prompt_message",
        "prompt message content is not an array",
        `${path}.content`,
      );
      continue;
    }
    const converted = collectParts(parts, context, `${path}.content`);
    if (message.role === "user") {
      steps.push(
        makeStep(steps.length + 1, "user", converted, { copied: true }),
      );
    } else if (message.role === "assistant") {
      steps.push(
        makeStep(steps.length + 1, "agent", converted, { copied: true }),
      );
    } else if (message.role === "tool") {
      const prior = steps.at(-1);
      const priorCallIds = new Set(
        prior?.source === "agent"
          ? (prior.tool_calls ?? []).map((call) => call.tool_call_id)
          : [],
      );
      const canAttachToPrior =
        prior?.source === "agent" &&
        converted.messageParts.length === 0 &&
        converted.reasoning.length === 0 &&
        converted.toolCalls.length === 0 &&
        Object.keys(converted.extra).length === 0 &&
        converted.observations.every(
          (result) =>
            result.source_call_id === undefined ||
            priorCallIds.has(result.source_call_id),
        );
      if (canAttachToPrior) {
        prior.observation = {
          results: [
            ...(prior.observation?.results ?? []),
            ...converted.observations,
          ],
        };
      } else {
        diagnostic(
          context.diagnostics,
          context.source.id,
          "detached_tool_result",
          "tool-role context could not be attached to its preceding agent action and remains a separate copied system observation",
          path,
        );
        const detached = converted.observations.map((result) => {
          const { source_call_id: sourceCallId, ...rest } = result;
          return {
            ...rest,
            ...(sourceCallId
              ? {
                  extra: {
                    ...(result.extra ?? {}),
                    apex_source_call_id: sourceCallId,
                  },
                }
              : {}),
          };
        });
        steps.push(
          makeStep(
            steps.length + 1,
            "system",
            {
              ...converted,
              observations: detached,
              toolCalls: [],
              reasoning: [],
            },
            {
              copied: true,
              extra: { source_role: "tool" },
            },
          ),
        );
      }
    } else {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "unsupported_prompt_role",
        `prompt role ${message.role} is retained only in source evidence`,
        path,
      );
    }
  }
  return steps;
}

function toolDefinitions(
  tools: JsonValue[] | undefined,
  context: ConversionContext,
): AtifToolDefinition[] {
  const definitions: AtifToolDefinition[] = [];
  for (const [index, raw] of (tools ?? []).entries()) {
    const tool = asObject(raw);
    const parameters = asObject(tool?.inputSchema);
    if (
      tool?.type === "function" &&
      typeof tool.name === "string" &&
      parameters
    ) {
      definitions.push({
        type: "function",
        function: {
          name: tool.name,
          ...(typeof tool.description === "string"
            ? { description: tool.description }
            : {}),
          parameters,
        },
      });
    } else {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "unsupported_tool_definition",
        "provider-defined or malformed tool definition remains only in source evidence",
        `tools[${index}]`,
      );
    }
  }
  return definitions;
}

function evidenceAsset(
  evidence: NativeRolloutEvidenceEnvelopeV1,
  reference: { ref: string },
): JsonValue | undefined {
  return evidence.assets.find((asset) => asset.ref === reference.ref)?.content;
}

function availableValue<T>(
  availability: EvidenceAvailability<T>,
): T | undefined {
  return availability.state === "available" ? availability.value : undefined;
}

function integer(value: JsonValue | undefined): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0
    ? value
    : undefined;
}

function metricsFromEvidence(
  evidence: NativeRolloutEvidenceEnvelopeV1,
  usage: JsonObject | undefined,
  context: ConversionContext,
): AtifMetrics | undefined {
  const input = asObject(usage?.inputTokens);
  const output = asObject(usage?.outputTokens);
  const promptTokens = integer(input?.total);
  const completionTokens = integer(output?.total);
  const observedCachedTokens = integer(input?.cacheRead);
  const cachedTokens =
    observedCachedTokens !== undefined &&
    promptTokens !== undefined &&
    observedCachedTokens > promptTokens
      ? undefined
      : observedCachedTokens;
  if (observedCachedTokens !== undefined && cachedTokens === undefined) {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "misaligned_cached_tokens",
      "cached input tokens exceed total prompt tokens and remain only in source evidence",
      "output.usage.inputTokens",
    );
  }
  const aligned = (
    field: string,
    values: number[] | undefined,
    count: number | undefined,
  ): number[] | undefined => {
    if (
      values === undefined ||
      count === undefined ||
      values.length === count
    ) {
      return values;
    }
    diagnostic(
      context.diagnostics,
      context.source.id,
      "misaligned_native_metric",
      `${field} length does not match the recorded token count and remains only in source evidence`,
      `native.${field}`,
    );
    return undefined;
  };
  const promptIds = aligned(
    "promptTokenIds",
    availableValue(evidence.native.promptTokenIds),
    promptTokens,
  );
  const completionIds = aligned(
    "completionTokenIds",
    availableValue(evidence.native.completionTokenIds),
    completionTokens,
  );
  const logprobs = aligned(
    "logprobs",
    availableValue(evidence.native.logprobs),
    completionTokens,
  );
  const extra: JsonObject = {
    apex_native_availability: {
      prompt_token_ids: evidence.native.promptTokenIds.state,
      completion_token_ids: evidence.native.completionTokenIds.state,
      logprobs: evidence.native.logprobs.state,
      tokenizer: evidence.native.tokenizer.state,
      extra: evidence.native.extra.state,
    },
  };
  const tokenizer = availableValue(evidence.native.tokenizer);
  if (tokenizer) extra.tokenizer = tokenizer;
  const providerExtra = availableValue(evidence.native.extra);
  if (providerExtra) extra.provider = providerExtra;
  const metrics: AtifMetrics = {
    ...(promptTokens !== undefined ? { prompt_tokens: promptTokens } : {}),
    ...(completionTokens !== undefined
      ? { completion_tokens: completionTokens }
      : {}),
    ...(cachedTokens !== undefined ? { cached_tokens: cachedTokens } : {}),
    ...(promptIds ? { prompt_token_ids: promptIds } : {}),
    ...(completionIds ? { completion_token_ids: completionIds } : {}),
    ...(logprobs ? { logprobs } : {}),
    extra,
  };
  return Object.keys(metrics).length > 1 || Object.keys(extra).length > 0
    ? metrics
    : undefined;
}

function collectStreamOutput(
  parts: JsonValue[],
  context: ConversionContext,
): { content: StepContent; usage?: JsonObject } {
  const output = emptyStepContent();
  const text = new Map<string, Extract<AtifContentPart, { type: "text" }>>();
  const reasoning = new Map<string, string>();
  const partialTools = new Map<string, { name: string; input: string }>();
  let usage: JsonObject | undefined;
  for (const [index, raw] of parts.entries()) {
    const part = asObject(raw);
    if (!part || typeof part.type !== "string") continue;
    const path = `output.parts[${index}]`;
    if (
      (part.type === "text-start" || part.type === "text-delta") &&
      typeof part.id === "string"
    ) {
      let value = text.get(part.id);
      if (!value) {
        value = { type: "text", text: "" };
        text.set(part.id, value);
        output.messageParts.push(value);
      }
      if (part.type === "text-delta" && typeof part.delta === "string") {
        value.text += part.delta;
      }
    } else if (part.type === "reasoning-delta" && typeof part.id === "string") {
      reasoning.set(
        part.id,
        `${reasoning.get(part.id) ?? ""}${part.delta ?? ""}`,
      );
    } else if (
      part.type === "tool-input-start" &&
      typeof part.id === "string" &&
      typeof part.toolName === "string"
    ) {
      partialTools.set(part.id, { name: part.toolName, input: "" });
    } else if (
      part.type === "tool-input-delta" &&
      typeof part.id === "string"
    ) {
      const pending = partialTools.get(part.id);
      if (pending && typeof part.delta === "string")
        pending.input += part.delta;
    } else if (part.type === "tool-call") {
      const call = toolCallFromPart(part, context, path);
      if (call) {
        output.toolCalls.push(call);
        partialTools.delete(call.tool_call_id);
      }
    } else if (part.type === "tool-result") {
      const result = toolResultFromPart(part, context, path);
      if (result) output.observations.push(result);
    } else if (part.type === "file") {
      const converted = contentPartFromFile(part, context, path);
      if (converted) output.messageParts.push(converted);
    } else if (part.type === "source") {
      const sources = (output.extra.sources as JsonValue[] | undefined) ?? [];
      sources.push(part);
      output.extra.sources = sources;
    } else if (part.type === "finish") {
      usage = asObject(part.usage);
      output.extra.finish_reason = part.finishReason ?? null;
    } else if (part.type === "error") {
      diagnostic(
        context.diagnostics,
        context.source.id,
        "stream_error",
        "captured stream contains an error part",
        path,
      );
    }
  }
  output.reasoning.push(...reasoning.values());
  for (const [id] of partialTools) {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "partial_tool_call",
      `stream ended before tool call ${id} completed`,
      "output.parts",
    );
  }
  return { content: output, usage };
}

function outputStep(
  evidence: NativeRolloutEvidenceEnvelopeV1,
  context: ConversionContext,
  stepId: number,
): AtifStep {
  const outputReference = availableValue(evidence.boundary.output.normalized);
  const partialReference =
    evidence.boundary.output.normalized.state === "truncated" ||
    evidence.boundary.output.normalized.state === "interrupted"
      ? evidence.boundary.output.normalized.partial
      : undefined;
  const output = outputReference ?? partialReference;
  const normalized = output ? evidenceAsset(evidence, output) : undefined;
  let content = emptyStepContent();
  let usage: JsonObject | undefined;
  const normalizedObject = asObject(normalized);
  const generatedContent = asArray(normalizedObject?.content);
  const streamedParts = asArray(normalizedObject?.parts);
  if (generatedContent) {
    content = collectParts(generatedContent, context, "output.content");
    usage = asObject(normalizedObject?.usage);
    if (normalizedObject?.finishReason !== undefined) {
      content.extra.finish_reason = normalizedObject.finishReason;
    }
  } else if (streamedParts) {
    const streamed = collectStreamOutput(streamedParts, context);
    content = streamed.content;
    usage = streamed.usage;
  } else if (normalized === undefined) {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "missing_output",
      "attempt has no recorded normalized model output",
      "boundary.output.normalized",
    );
  } else {
    diagnostic(
      context.diagnostics,
      context.source.id,
      "unsupported_output_shape",
      "normalized output shape is retained only in source evidence",
      "boundary.output.normalized",
    );
  }
  content.extra.apex_attempt = {
    attempt_id: evidence.attempt.attemptId,
    idempotency_key: evidence.attempt.idempotencyKey,
    sequence: evidence.attempt.sequence,
    root_attempt_id: evidence.attempt.rootAttemptId,
    ...(evidence.attempt.previousAttemptId
      ? { previous_attempt_id: evidence.attempt.previousAttemptId }
      : {}),
    lifecycle: evidence.attempt.lifecycle,
    turn_id: evidence.turnId,
    turn_index: evidence.turnIndex,
    segment_id: evidence.segmentId,
    operation_kind: evidence.operationKind,
  };
  return makeStep(stepId, "agent", content, {
    copied: false,
    modelName: evidence.effective.modelId,
    metrics: metricsFromEvidence(evidence, usage, context),
  });
}

function sourceContext(
  evidence: NativeRolloutEvidenceEnvelopeV1,
  source: ParsedNativeRolloutSource,
): JsonObject {
  const availability = (
    value: EvidenceAvailability<{ ref: string }>,
  ): JsonObject => ({
    state: value.state,
    ...(value.state === "available"
      ? { ref: value.value.ref }
      : value.state === "truncated" || value.state === "interrupted"
        ? {
            reason: value.reason,
            ...(value.partial ? { ref: value.partial.ref } : {}),
            ...(value.observed ? { observed: value.observed } : {}),
          }
        : { reason: value.reason }),
  });
  return {
    native_evidence: {
      schema: evidence.schema,
      version: evidence.version,
      run_id: evidence.runId,
      ...(evidence.sessionId ? { session_id: evidence.sessionId } : {}),
    },
    source: {
      id: source.id,
      path: `sources/${source.id}.json`,
      sha256: source.sha256,
      size_bytes: source.sizeBytes,
    },
    boundary: {
      input: {
        normalized_ref: evidence.boundary.input.normalizedRef.ref,
        native: availability(evidence.boundary.input.native),
      },
      output: {
        normalized: availability(evidence.boundary.output.normalized),
        native: availability(evidence.boundary.output.native),
      },
    },
    requested_model: evidence.requested,
    effective_model: evidence.effective,
  };
}

function trajectoryId(evidence: NativeRolloutEvidenceEnvelopeV1): string {
  return `atif_${evidence.attempt.attemptId}`;
}

function documentPath(id: string): string {
  return `trajectories/${id}.json`;
}

function convertSource(
  source: ParsedNativeRolloutSource,
  agentIdentity: ConvertNativeRolloutToAtifInput["agent"],
  assets: AssetCollector,
  diagnostics: AtifDiagnostic[],
): AtifTrajectoryV1_8 {
  const evidence = source.evidence;
  if (evidence.attempt.lifecycle !== "completed") {
    diagnostic(
      diagnostics,
      source.id,
      "incomplete_attempt_lifecycle",
      `attempt lifecycle is ${evidence.attempt.lifecycle}`,
      "attempt.lifecycle",
    );
  }
  for (const limitation of evidence.limitations) {
    diagnostic(
      diagnostics,
      source.id,
      `source_${limitation.code}`,
      limitation.message,
      limitation.field,
    );
  }
  for (const asset of evidence.assets) {
    assets.addJson(asset.sha256, asset.mediaType, asset.content, source.id);
  }
  const context: ConversionContext = { source, assets, diagnostics };
  const normalizedInput = evidenceAsset(
    evidence,
    evidence.boundary.input.normalizedRef,
  );
  const input = asObject(normalizedInput);
  const steps = promptSteps(asArray(input?.prompt), context);
  steps.push(outputStep(evidence, context, steps.length + 1));
  const definitions = toolDefinitions(asArray(input?.tools), context);
  const agent: AtifAgent = {
    ...agentIdentity,
    model_name: evidence.requested.modelId,
    ...(definitions.length > 0 ? { tool_definitions: definitions } : {}),
    extra: {
      provider: evidence.requested.provider,
      operation_kind: evidence.operationKind,
    },
  };
  const outputMetrics = steps.at(-1)?.metrics;
  return {
    schema_version: ATIF_SCHEMA_VERSION,
    session_id: evidence.sessionId ?? evidence.runId,
    trajectory_id: trajectoryId(evidence),
    agent,
    steps,
    notes:
      "Each document is one physical model attempt. Input steps are the exact recorded call context and are marked copied context; the final agent step is this attempt's output.",
    final_metrics: {
      total_steps: steps.length,
      ...(outputMetrics?.prompt_tokens !== undefined
        ? { total_prompt_tokens: outputMetrics.prompt_tokens }
        : {}),
      ...(outputMetrics?.completion_tokens !== undefined
        ? { total_completion_tokens: outputMetrics.completion_tokens }
        : {}),
      ...(outputMetrics?.cached_tokens !== undefined
        ? { total_cached_tokens: outputMetrics.cached_tokens }
        : {}),
    },
    extra: sourceContext(evidence, source),
  };
}

function emptyAvailabilityCounts(): AvailabilityCounts {
  return {
    available: 0,
    unsupported: 0,
    omitted: 0,
    truncated: 0,
    interrupted: 0,
  };
}

function nativeSamplingSummary(
  sources: ParsedNativeRolloutSource[],
): NativeSamplingSummary {
  const summary: NativeSamplingSummary = {
    promptTokenIds: emptyAvailabilityCounts(),
    completionTokenIds: emptyAvailabilityCounts(),
    logprobs: emptyAvailabilityCounts(),
    tokenizer: emptyAvailabilityCounts(),
    extra: emptyAvailabilityCounts(),
  };
  for (const { evidence } of sources) {
    summary.promptTokenIds[evidence.native.promptTokenIds.state] += 1;
    summary.completionTokenIds[evidence.native.completionTokenIds.state] += 1;
    summary.logprobs[evidence.native.logprobs.state] += 1;
    summary.tokenizer[evidence.native.tokenizer.state] += 1;
    summary.extra[evidence.native.extra.state] += 1;
  }
  return summary;
}

function recordMissingAssociations(
  documents: Iterable<AtifTrajectoryV1_8>,
  diagnostics: AtifDiagnostic[],
): void {
  const results = new Set<string>();
  const calls = new Map<string, string>();
  for (const document of documents) {
    for (const step of document.steps) {
      for (const result of step.observation?.results ?? []) {
        if (result.source_call_id) results.add(result.source_call_id);
      }
      if (step.is_copied_context) continue;
      for (const call of step.tool_calls ?? []) {
        calls.set(call.tool_call_id, document.trajectory_id ?? "trajectory");
      }
    }
  }
  for (const [callId, id] of calls) {
    if (!results.has(callId)) {
      diagnostics.push({
        code: "missing_tool_result",
        severity: "warning",
        message: `tool call ${callId} has no recorded result in this bundle`,
        path: id,
      });
    }
  }
}

export function convertNativeRolloutSourcesToAtif(
  input: ConvertNativeRolloutToAtifInput,
): AtifConversionDraft {
  const sources = parseSources(input.sources);
  const root = sources.find((source) => source.id === input.rootSourceId);
  if (!root) {
    throw new AtifConversionError("rootSourceId does not resolve", [
      {
        code: "unresolved_root_source",
        severity: "error",
        message: "rootSourceId must identify one supplied source",
      },
    ]);
  }
  const diagnostics: AtifDiagnostic[] = [];
  const assets = createAssetCollector(diagnostics);
  const sorted = [...sources].sort((left, right) => {
    const leftSession = left.evidence.sessionId ?? left.evidence.runId;
    const rightSession = right.evidence.sessionId ?? right.evidence.runId;
    return (
      leftSession.localeCompare(rightSession) ||
      left.evidence.turnIndex - right.evidence.turnIndex ||
      left.evidence.attempt.sequence - right.evidence.attempt.sequence ||
      left.id.localeCompare(right.id)
    );
  });
  const documents = Object.create(null) as Record<string, AtifTrajectoryV1_8[]>;
  const documentPaths = new Map<string, string>();
  for (const source of sorted) {
    const document = convertSource(source, input.agent, assets, diagnostics);
    const id = document.trajectory_id;
    const sessionId = document.session_id;
    if (!id || !sessionId) {
      diagnostic(
        diagnostics,
        source.id,
        "missing_document_identity",
        "converted ATIF documents require trajectory_id and session_id",
        "trajectory",
        "error",
      );
      continue;
    }
    if (documentPaths.has(id)) {
      diagnostic(
        diagnostics,
        source.id,
        "duplicate_trajectory_id",
        `trajectory id ${id} is not unique`,
        id,
        "error",
      );
      continue;
    }
    documentPaths.set(id, documentPath(id));
    const sessionDocuments = documents[sessionId] ?? [];
    sessionDocuments.push(document);
    documents[sessionId] = sessionDocuments;
  }
  for (const sessionDocuments of Object.values(documents)) {
    for (let index = 0; index < sessionDocuments.length - 1; index++) {
      const current = sessionDocuments[index];
      const nextId = sessionDocuments[index + 1]?.trajectory_id;
      if (current && nextId) {
        current.continued_trajectory_ref = documentPath(nextId);
      }
    }
  }
  const allDocuments = Object.values(documents).flat();
  recordMissingAssociations(allDocuments, diagnostics);
  if (Object.keys(documents).length > 1) {
    diagnostics.push({
      code: "session_relationships_unavailable",
      severity: "warning",
      message:
        "recorded inference evidence does not establish parent-child relationships between sessions",
    });
  }
  const files: DraftFile[] = [
    ...sources.map((source) => ({
      kind: "source" as const,
      path: `sources/${source.id}.json`,
      mediaType: "application/json",
      bytes: source.bytes,
    })),
    ...assets.files.values(),
  ].sort((left, right) => left.path.localeCompare(right.path));
  return {
    rootTrajectoryId: trajectoryId(root.evidence),
    exporter: input.exporter,
    documents,
    documentPaths,
    files,
    diagnostics,
    nativeSampling: nativeSamplingSummary(sources),
    ...(input.independentValidation
      ? { independentValidation: input.independentValidation }
      : {}),
  };
}

import { z } from "zod";
import {
  type JsonValue,
  JsonValueSchema,
  NATIVE_EVIDENCE_AVAILABILITY_STATES,
  type NativeRolloutEvidenceEnvelopeV1,
} from "../ai/native-rollout-evidence";

export const ATIF_SCHEMA_VERSION = "ATIF-v1.8" as const;
export const ATIF_REFERENCE_REVISION =
  "88fdbc9d42e907c0414654f041ece5eaf798f538" as const;
export const TRAJECTORY_BUNDLE_TYPE = "evalgate.trajectory-bundle" as const;
export const TRAJECTORY_BUNDLE_VERSION = 1 as const;
export const APEX_ATIF_EXPORTER_VERSION = 1 as const;
export const ATIF_EXPORT_SOURCE_LIMITS = {
  maxSources: 512,
  maxTotalSourceBytes: 64 * 1024 * 1024,
} as const;

export type JsonObject = { [key: string]: JsonValue };

const JsonObjectSchema: z.ZodType<JsonObject> = JsonValueSchema.refine(
  (value): value is JsonObject =>
    typeof value === "object" && value !== null && !Array.isArray(value),
  { message: "expected a JSON object" },
);

export const AtifTextContentPartSchema = z.strictObject({
  type: z.literal("text"),
  text: z.string(),
});

export const AtifImageSourceSchema = z.strictObject({
  media_type: z.enum(["image/jpeg", "image/png", "image/gif", "image/webp"]),
  path: z.string().min(1),
});

export const AtifAudioSourceSchema = z.strictObject({
  media_type: z.enum([
    "audio/wav",
    "audio/mpeg",
    "audio/mp4",
    "audio/aac",
    "audio/ogg",
    "audio/flac",
    "audio/webm",
    "audio/aiff",
  ]),
  path: z.string().min(1),
  duration_sec: z.number().finite().nonnegative().optional(),
});

export const AtifContentPartSchema = z.discriminatedUnion("type", [
  AtifTextContentPartSchema,
  z.strictObject({
    type: z.literal("image"),
    source: AtifImageSourceSchema,
  }),
  z.strictObject({
    type: z.literal("audio"),
    source: AtifAudioSourceSchema,
  }),
]);
export type AtifContentPart = z.infer<typeof AtifContentPartSchema>;
export type AtifMessage = string | AtifContentPart[];

export const AtifToolDefinitionSchema = z.strictObject({
  type: z.literal("function"),
  function: z.strictObject({
    name: z.string().min(1),
    description: z.string().optional(),
    parameters: JsonObjectSchema,
  }),
});
export type AtifToolDefinition = z.infer<typeof AtifToolDefinitionSchema>;

export const AtifAgentSchema = z.strictObject({
  name: z.string().min(1),
  version: z.string().min(1),
  model_name: z.string().min(1).optional(),
  tool_definitions: z.array(AtifToolDefinitionSchema).optional(),
  extra: JsonObjectSchema.optional(),
});
export type AtifAgent = z.infer<typeof AtifAgentSchema>;

export const AtifToolCallSchema = z.strictObject({
  tool_call_id: z.string().min(1),
  function_name: z.string().min(1),
  arguments: JsonObjectSchema,
  extra: JsonObjectSchema.optional(),
});
export type AtifToolCall = z.infer<typeof AtifToolCallSchema>;

export const AtifSubagentTrajectoryRefSchema = z
  .strictObject({
    trajectory_id: z.string().min(1).optional(),
    trajectory_path: z.string().min(1).optional(),
    session_id: z.string().min(1).optional(),
    extra: JsonObjectSchema.optional(),
  })
  .refine(
    (value) =>
      value.trajectory_id !== undefined || value.trajectory_path !== undefined,
    { message: "a subagent reference needs trajectory_id or trajectory_path" },
  );
export type AtifSubagentTrajectoryRef = z.infer<
  typeof AtifSubagentTrajectoryRefSchema
>;

export const AtifObservationResultSchema = z
  .strictObject({
    source_call_id: z.string().min(1).optional(),
    content: z.union([z.string(), z.array(AtifContentPartSchema)]).optional(),
    subagent_trajectory_ref: z
      .array(AtifSubagentTrajectoryRefSchema)
      .optional(),
    extra: JsonObjectSchema.optional(),
  })
  .refine(
    (value) =>
      value.content !== undefined ||
      (value.subagent_trajectory_ref?.length ?? 0) > 0,
    { message: "an observation result needs content or a subagent reference" },
  );
export type AtifObservationResult = z.infer<typeof AtifObservationResultSchema>;

export const AtifMetricsSchema = z.strictObject({
  prompt_tokens: z.number().int().nonnegative().optional(),
  completion_tokens: z.number().int().nonnegative().optional(),
  cached_tokens: z.number().int().nonnegative().optional(),
  cost_usd: z.number().finite().nonnegative().optional(),
  prompt_token_ids: z.array(z.number().int().nonnegative()).optional(),
  completion_token_ids: z.array(z.number().int().nonnegative()).optional(),
  logprobs: z.array(z.number().finite()).optional(),
  extra: JsonObjectSchema.optional(),
});
export type AtifMetrics = z.infer<typeof AtifMetricsSchema>;

export const AtifStepSchema = z.strictObject({
  step_id: z.number().int().positive(),
  timestamp: z.string().min(1).optional(),
  source: z.enum(["system", "user", "agent"]),
  model_name: z.string().min(1).optional(),
  reasoning_effort: z.union([z.string(), z.number().finite()]).optional(),
  message: z.union([z.string(), z.array(AtifContentPartSchema)]),
  reasoning_content: z.string().optional(),
  tool_calls: z.array(AtifToolCallSchema).optional(),
  observation: z
    .strictObject({ results: z.array(AtifObservationResultSchema) })
    .optional(),
  metrics: AtifMetricsSchema.optional(),
  extra: JsonObjectSchema.optional(),
  llm_call_count: z.number().int().nonnegative().optional(),
  is_copied_context: z.boolean().optional(),
});
export type AtifStep = z.infer<typeof AtifStepSchema>;

export const AtifFinalMetricsSchema = z.strictObject({
  total_prompt_tokens: z.number().int().nonnegative().optional(),
  total_completion_tokens: z.number().int().nonnegative().optional(),
  total_cached_tokens: z.number().int().nonnegative().optional(),
  total_cost_usd: z.number().finite().nonnegative().optional(),
  total_steps: z.number().int().nonnegative().optional(),
  extra: JsonObjectSchema.optional(),
});
export type AtifFinalMetrics = z.infer<typeof AtifFinalMetricsSchema>;

export interface AtifTrajectoryV1_8 {
  schema_version: typeof ATIF_SCHEMA_VERSION;
  session_id?: string;
  trajectory_id?: string;
  agent: AtifAgent;
  steps: AtifStep[];
  notes?: string;
  final_metrics?: AtifFinalMetrics;
  continued_trajectory_ref?: string;
  extra?: JsonObject;
  subagent_trajectories?: AtifTrajectoryV1_8[];
}

export const AtifTrajectorySchema: z.ZodType<AtifTrajectoryV1_8> = z.lazy(() =>
  z.strictObject({
    schema_version: z.literal(ATIF_SCHEMA_VERSION),
    session_id: z.string().min(1).optional(),
    trajectory_id: z.string().min(1).optional(),
    agent: AtifAgentSchema,
    steps: z.array(AtifStepSchema).min(1),
    notes: z.string().optional(),
    final_metrics: AtifFinalMetricsSchema.optional(),
    continued_trajectory_ref: z.string().min(1).optional(),
    extra: JsonObjectSchema.optional(),
    subagent_trajectories: z.array(AtifTrajectorySchema).optional(),
  }),
);

export const AtifDiagnosticSchema = z.strictObject({
  code: z.string().min(1),
  severity: z.enum(["error", "warning"]),
  message: z.string().min(1),
  path: z.string().min(1).optional(),
  sourceId: z.string().min(1).optional(),
});
export type AtifDiagnostic = z.infer<typeof AtifDiagnosticSchema>;

const bundleFileEntrySchema = z.strictObject({
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  sizeBytes: z.number().int().nonnegative(),
});

export const TrajectoryBundleManifestSchema = z.strictObject({
  type: z.literal(TRAJECTORY_BUNDLE_TYPE),
  version: z.literal(TRAJECTORY_BUNDLE_VERSION),
  rootTrajectoryId: z.string().min(1),
  atif: z.strictObject({
    schemaVersion: z.literal(ATIF_SCHEMA_VERSION),
    referenceRevision: z.literal(ATIF_REFERENCE_REVISION),
  }),
  exporter: z.strictObject({
    name: z.string().min(1),
    version: z.string().min(1),
  }),
  documents: z.array(
    bundleFileEntrySchema.extend({ trajectoryId: z.string().min(1) }),
  ),
  assets: z.array(
    bundleFileEntrySchema.extend({
      mediaType: z.string().min(1),
      required: z.boolean(),
    }),
  ),
  sources: z.array(bundleFileEntrySchema.extend({ id: z.string().min(1) })),
  validation: z.strictObject({
    status: z.enum(["passed", "failed"]),
    validator: z.strictObject({
      name: z.literal("apex-atif-v1.8"),
      version: z.literal(APEX_ATIF_EXPORTER_VERSION),
    }),
    independent: z.strictObject({
      status: z.enum(["not_run", "passed", "failed"]),
      detail: z.string().min(1),
    }),
    diagnostics: z.array(AtifDiagnosticSchema),
  }),
  completeness: z.strictObject({
    transcript: z.enum(["complete", "partial"]),
    sftEligibility: z.enum(["eligible", "ineligible"]),
    rlEligibility: z.enum(["eligible", "ineligible"]),
    diagnostics: z.array(AtifDiagnosticSchema),
  }),
  nativeSampling: z.record(
    z.enum([
      "promptTokenIds",
      "completionTokenIds",
      "logprobs",
      "tokenizer",
      "extra",
    ]),
    z.record(
      z.enum(NATIVE_EVIDENCE_AVAILABILITY_STATES),
      z.number().int().nonnegative(),
    ),
  ),
});
export type TrajectoryBundleManifestV1 = z.infer<
  typeof TrajectoryBundleManifestSchema
>;

export interface RecordedNativeRolloutSource {
  id: string;
  sha256: string;
  sizeBytes: number;
  bytes: Uint8Array;
}

export interface AtifExporterIdentity {
  name: string;
  version: string;
}

export interface ConvertNativeRolloutToAtifInput {
  sources: readonly RecordedNativeRolloutSource[];
  rootSourceId: string;
  agent: Pick<AtifAgent, "name" | "version">;
  exporter: AtifExporterIdentity;
  independentValidation?: {
    status: "passed" | "failed";
    detail: string;
  };
}

export interface ParsedNativeRolloutSource
  extends Omit<RecordedNativeRolloutSource, "bytes"> {
  bytes: Uint8Array;
  evidence: NativeRolloutEvidenceEnvelopeV1;
}

export interface AtifBundleFile {
  kind: "manifest" | "document" | "asset" | "source";
  path: string;
  mediaType: string;
  bytes: Uint8Array;
  sha256: string;
  sizeBytes: number;
}

export interface AtifExportBundleV1 {
  manifest: TrajectoryBundleManifestV1;
  documents: Readonly<Record<string, readonly AtifTrajectoryV1_8[]>>;
  files: readonly AtifBundleFile[];
}

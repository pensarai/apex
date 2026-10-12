import { isAbsolute } from "node:path";
import { z } from "zod";
import type { ToolName } from "../agents/offSecAgent";
import { isSessionId } from "../id/id";

// Browser and orchestration tools require additional environment/child state.
const RECORDED_RUN_TOOL_ALLOWLIST = [
  "read_file",
  "list_files",
  "grep",
  "execute_command",
  "http_request",
  "document_vulnerability",
  "write_plan",
  "create_task",
  "update_task",
  "list_tasks",
] as const satisfies readonly ToolName[];

const RUN_ID_PATTERN = /^run_[A-Za-z0-9_-]{1,62}$/;
const ATTEMPT_ID_PATTERN =
  /^exec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const runEnvironmentShape = {
  kind: z.literal("local"),
  cwd: z
    .string()
    .refine(isAbsolute, { message: "environment.cwd must be absolute" }),
};

const runScopeShape = {
  version: z.literal(1),
  allowedHosts: z.array(z.string().min(1)),
  allowedPorts: z.array(z.number().int().min(1).max(65535)),
  strictScope: z.boolean(),
  allowDestructiveActions: z.boolean(),
  allowRateLimitTesting: z.boolean(),
};

// Both schemas retain this key order for normalized admission equality.
const recordedRunSpecShape = {
  schemaVersion: z.literal(1),
  configVersion: z.literal(1),
  runId: z.string().regex(RUN_ID_PATTERN, {
    message: "runId must be run_ followed by 1-62 [A-Za-z0-9_-] characters",
  }),
  prompt: z.string().min(1),
  target: z.string().min(1),
  model: z.string().min(1),
  system: z.string().min(1).optional(),
  activeTools: z.array(z.enum(RECORDED_RUN_TOOL_ALLOWLIST)).min(1),
  environment: z.object(runEnvironmentShape).strict(),
  scope: z.object(runScopeShape).strict(),
  credentialRefs: z.array(z.string().min(1)),
  approval: z
    .object({
      requiredTools: z
        .array(z.enum(RECORDED_RUN_TOOL_ALLOWLIST))
        .refine((tools) => new Set(tools).size === tools.length),
    })
    .strict()
    .optional(),
  limits: z
    .object({
      maxModelAttempts: z.number().int().positive().optional(),
      deadlineAt: z.iso.datetime().optional(),
    })
    .strict()
    .optional(),
};

export const RecordedRunSpecSchema = z
  .object({
    ...recordedRunSpecShape,
    scope: z
      .object({
        ...runScopeShape,
        allowedHosts: runScopeShape.allowedHosts.default([]),
        allowedPorts: runScopeShape.allowedPorts.default([]),
        allowDestructiveActions:
          runScopeShape.allowDestructiveActions.default(false),
        allowRateLimitTesting:
          runScopeShape.allowRateLimitTesting.default(false),
      })
      .strict(),
    credentialRefs: recordedRunSpecShape.credentialRefs.default([]),
  })
  .strict()
  .refine(
    (spec) =>
      spec.approval?.requiredTools.every((tool) =>
        spec.activeTools.includes(tool),
      ) ?? true,
    {
      message: "Approval tools must be enabled in activeTools",
    },
  );

export type RecordedRunSpec = z.output<typeof RecordedRunSpecSchema>;

// Stored records must not repair missing fields by applying admission defaults.
export const RunRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    spec: z
      .object(recordedRunSpecShape)
      .strict()
      .refine(
        (spec) =>
          spec.approval?.requiredTools.every((tool) =>
            spec.activeTools.includes(tool),
          ) ?? true,
      ),
    sessionId: z
      .string()
      .refine(isSessionId, { message: "sessionId must be a ses_ session id" }),
    attemptId: z.string().regex(ATTEMPT_ID_PATTERN, {
      message: "attemptId must be exec_ followed by a UUID",
    }),
    runtimeVersion: z.string().min(1),
    status: z.enum([
      "admitted",
      "running",
      "paused",
      "completed",
      "failed",
      "cancelled",
    ]),
    admittedAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
  })
  .strict();

export type RunRecord = z.output<typeof RunRecordSchema>;

export interface RunStore {
  /** Atomically admit once; identical retries return the record, changed inputs reject. */
  admit(
    spec: RecordedRunSpec,
  ): Promise<{ created: boolean; record: RunRecord }>;
  get(runId: string): Promise<RunRecord | undefined>;
  list(): Promise<RunRecord[]>;
  transition(
    runId: string,
    attemptId: string,
    status: "running" | "paused" | "completed" | "failed" | "cancelled",
  ): Promise<RunRecord>;
}

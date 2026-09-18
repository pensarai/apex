import type { AtifDiagnostic, AtifStep, AtifTrajectoryV1_8 } from "./schema";
import { AtifTrajectorySchema } from "./schema";

export type AtifValidationCode =
  | "invalid-document"
  | "invalid-step-sequence"
  | "invalid-step-fields"
  | "invalid-timestamp"
  | "duplicate-tool-call"
  | "unresolved-tool-result"
  | "invalid-metrics"
  | "duplicate-trajectory-id"
  | "unresolved-subagent-reference";

const ISO_8601_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export class AtifValidationError extends Error {
  readonly diagnostics: AtifDiagnostic[];

  constructor(diagnostics: AtifDiagnostic[]) {
    super(diagnostics[0]?.message ?? "ATIF validation failed");
    this.name = "AtifValidationError";
    this.diagnostics = diagnostics;
  }
}

function error(
  diagnostics: AtifDiagnostic[],
  code: AtifValidationCode,
  message: string,
  path: string,
): void {
  diagnostics.push({ code, severity: "error", message, path });
}

function validateMetrics(
  step: AtifStep,
  path: string,
  diagnostics: AtifDiagnostic[],
): void {
  const metrics = step.metrics;
  if (!metrics) return;
  if (
    metrics.prompt_token_ids !== undefined &&
    metrics.prompt_tokens !== undefined &&
    metrics.prompt_token_ids.length !== metrics.prompt_tokens
  ) {
    error(
      diagnostics,
      "invalid-metrics",
      "prompt_token_ids length must match prompt_tokens",
      `${path}.metrics`,
    );
  }
  if (
    metrics.completion_token_ids !== undefined &&
    metrics.completion_tokens !== undefined &&
    metrics.completion_token_ids.length !== metrics.completion_tokens
  ) {
    error(
      diagnostics,
      "invalid-metrics",
      "completion_token_ids length must match completion_tokens",
      `${path}.metrics`,
    );
  }
  if (
    metrics.logprobs !== undefined &&
    metrics.completion_tokens !== undefined &&
    metrics.logprobs.length !== metrics.completion_tokens
  ) {
    error(
      diagnostics,
      "invalid-metrics",
      "logprobs length must match completion_tokens",
      `${path}.metrics`,
    );
  }
  if (
    metrics.completion_token_ids !== undefined &&
    metrics.logprobs !== undefined &&
    metrics.completion_token_ids.length !== metrics.logprobs.length
  ) {
    error(
      diagnostics,
      "invalid-metrics",
      "completion_token_ids and logprobs must align",
      `${path}.metrics`,
    );
  }
  if (
    metrics.cached_tokens !== undefined &&
    metrics.prompt_tokens !== undefined &&
    metrics.cached_tokens > metrics.prompt_tokens
  ) {
    error(
      diagnostics,
      "invalid-metrics",
      "cached_tokens cannot exceed prompt_tokens",
      `${path}.metrics`,
    );
  }
}

function validateStepFields(
  step: AtifStep,
  path: string,
  diagnostics: AtifDiagnostic[],
): void {
  if (
    step.source !== "agent" &&
    (step.model_name !== undefined ||
      step.reasoning_effort !== undefined ||
      step.reasoning_content !== undefined ||
      step.tool_calls !== undefined ||
      step.metrics !== undefined)
  ) {
    error(
      diagnostics,
      "invalid-step-fields",
      "model, reasoning, tool calls, and metrics are agent-only fields",
      path,
    );
  }
  if (step.source === "user" && step.observation !== undefined) {
    error(
      diagnostics,
      "invalid-step-fields",
      "user steps cannot carry an observation",
      path,
    );
  }
  if (
    step.source === "agent" &&
    step.llm_call_count === 0 &&
    (step.metrics !== undefined || step.reasoning_content !== undefined)
  ) {
    error(
      diagnostics,
      "invalid-step-fields",
      "a deterministic agent step cannot carry metrics or reasoning",
      path,
    );
  }
  if (
    step.timestamp !== undefined &&
    (!ISO_8601_PATTERN.test(step.timestamp) ||
      !Number.isFinite(Date.parse(step.timestamp)))
  ) {
    error(
      diagnostics,
      "invalid-timestamp",
      "timestamp must be a valid ISO 8601 value",
      `${path}.timestamp`,
    );
  }
  validateMetrics(step, path, diagnostics);
}

function validateTrajectory(
  trajectory: AtifTrajectoryV1_8,
  path: string,
  diagnostics: AtifDiagnostic[],
): void {
  const toolCalls = new Map<string, string>();
  for (const [index, step] of trajectory.steps.entries()) {
    const stepPath = `${path}.steps[${index}]`;
    if (step.step_id !== index + 1) {
      error(
        diagnostics,
        "invalid-step-sequence",
        "step_id values must start at 1 and remain sequential",
        `${stepPath}.step_id`,
      );
    }
    validateStepFields(step, stepPath, diagnostics);
    for (const call of step.tool_calls ?? []) {
      const prior = toolCalls.get(call.tool_call_id);
      if (prior) {
        error(
          diagnostics,
          "duplicate-tool-call",
          `tool_call_id ${call.tool_call_id} already appears at ${prior}`,
          `${stepPath}.tool_calls`,
        );
      } else {
        toolCalls.set(call.tool_call_id, stepPath);
      }
    }
    const stepCallIds = new Set(
      (step.tool_calls ?? []).map((call) => call.tool_call_id),
    );
    for (const [resultIndex, result] of (
      step.observation?.results ?? []
    ).entries()) {
      if (
        result.source_call_id !== undefined &&
        !stepCallIds.has(result.source_call_id)
      ) {
        error(
          diagnostics,
          "unresolved-tool-result",
          `source_call_id ${result.source_call_id} has no tool call on this step`,
          `${path}.steps[${index}].observation.results[${resultIndex}]`,
        );
      }
    }
  }

  const embedded = trajectory.subagent_trajectories ?? [];
  const embeddedById = new Map<string, number>();
  for (const [index, child] of embedded.entries()) {
    if (!child.trajectory_id) {
      error(
        diagnostics,
        "unresolved-subagent-reference",
        "an embedded subagent trajectory needs trajectory_id",
        `${path}.subagent_trajectories[${index}]`,
      );
    } else if (embeddedById.has(child.trajectory_id)) {
      error(
        diagnostics,
        "duplicate-trajectory-id",
        `embedded trajectory_id ${child.trajectory_id} is not unique`,
        `${path}.subagent_trajectories[${index}].trajectory_id`,
      );
    } else {
      embeddedById.set(child.trajectory_id, index);
    }
    validateTrajectory(
      child,
      `${path}.subagent_trajectories[${index}]`,
      diagnostics,
    );
  }

  for (const [stepIndex, step] of trajectory.steps.entries()) {
    for (const [resultIndex, result] of (
      step.observation?.results ?? []
    ).entries()) {
      for (const [refIndex, reference] of (
        result.subagent_trajectory_ref ?? []
      ).entries()) {
        if (
          reference.trajectory_path === undefined &&
          reference.trajectory_id !== undefined &&
          !embeddedById.has(reference.trajectory_id)
        ) {
          error(
            diagnostics,
            "unresolved-subagent-reference",
            `trajectory_id ${reference.trajectory_id} is not embedded`,
            `${path}.steps[${stepIndex}].observation.results[${resultIndex}].subagent_trajectory_ref[${refIndex}]`,
          );
        }
      }
    }
  }
}

export function collectAtifValidationDiagnostics(value: unknown): {
  trajectory?: AtifTrajectoryV1_8;
  diagnostics: AtifDiagnostic[];
} {
  const parsed = AtifTrajectorySchema.safeParse(value);
  if (!parsed.success) {
    return {
      diagnostics: parsed.error.issues.map((issue) => ({
        code: "invalid-document",
        severity: "error" as const,
        message: issue.message,
        path: issue.path.length > 0 ? issue.path.join(".") : "trajectory",
      })),
    };
  }
  const diagnostics: AtifDiagnostic[] = [];
  validateTrajectory(parsed.data, "trajectory", diagnostics);
  return { trajectory: parsed.data, diagnostics };
}

export function parseAtifTrajectory(value: unknown): AtifTrajectoryV1_8 {
  const result = collectAtifValidationDiagnostics(value);
  if (!result.trajectory || result.diagnostics.length > 0) {
    throw new AtifValidationError(result.diagnostics);
  }
  return result.trajectory;
}

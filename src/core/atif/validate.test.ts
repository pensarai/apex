import { describe, expect, it } from "vitest";
import type { AtifStep, AtifTrajectoryV1_8 } from "./schema";
import {
  type AtifValidationError,
  collectAtifValidationDiagnostics,
  parseAtifTrajectory,
} from "./validate";

function trajectory(): AtifTrajectoryV1_8 {
  return {
    schema_version: "ATIF-v1.8",
    session_id: "session-fixture",
    trajectory_id: "trajectory-fixture",
    agent: { name: "apex", version: "test" },
    steps: [
      { step_id: 1, source: "user", message: "Question" },
      {
        step_id: 2,
        source: "agent",
        message: "Answer",
        llm_call_count: 1,
      },
    ],
  };
}

function step(value: AtifTrajectoryV1_8, index: number): AtifStep {
  const selected = value.steps[index];
  if (!selected) throw new Error(`missing fixture step ${index}`);
  return selected;
}

describe("ATIF-v1.8 validation", () => {
  it("accepts a structurally and semantically valid document", () => {
    expect(parseAtifTrajectory(trajectory())).toEqual(trajectory());
  });

  it("preserves prototype-shaped own keys in JSON extension records", () => {
    const value = trajectory();
    value.extra = JSON.parse(
      '{"__proto__":{"marker":true},"constructor":{"__proto__":"nested"}}',
    );

    const parsed = parseAtifTrajectory(value);
    const extra = parsed.extra as Record<string, unknown>;
    const constructorValue = Reflect.get(extra, "constructor") as Record<
      string,
      unknown
    >;
    expect(Object.hasOwn(extra, "__proto__")).toBe(true);
    expect(Object.hasOwn(extra, "constructor")).toBe(true);
    expect(Object.hasOwn(constructorValue, "__proto__")).toBe(true);
  });

  it("rejects shifted steps and non-ISO timestamps", () => {
    const value = trajectory();
    value.steps[0] = {
      ...step(value, 0),
      step_id: 2,
      timestamp: "09/17/2026",
    };

    const result = collectAtifValidationDiagnostics(value);
    expect(result.diagnostics.map((entry) => entry.code)).toEqual([
      "invalid-step-sequence",
      "invalid-timestamp",
    ]);
  });

  it("requires at least one step", () => {
    const value = trajectory();
    value.steps = [];

    expect(
      collectAtifValidationDiagnostics(value).diagnostics.map(
        (entry) => entry.code,
      ),
    ).toEqual(["invalid-document"]);
  });

  it("rejects agent-only fields on user steps and invalid metrics", () => {
    const value = trajectory();
    value.steps[0] = {
      ...step(value, 0),
      model_name: "not-applicable",
      metrics: {
        prompt_tokens: 1,
        cached_tokens: 2,
        prompt_token_ids: [1, 2],
      },
    };

    expect(() => parseAtifTrajectory(value)).toThrowError(
      expect.objectContaining<Partial<AtifValidationError>>({
        name: "AtifValidationError",
      }),
    );
    expect(
      collectAtifValidationDiagnostics(value).diagnostics.map(
        (entry) => entry.code,
      ),
    ).toEqual(["invalid-step-fields", "invalid-metrics", "invalid-metrics"]);
  });

  it("rejects duplicate calls and unresolved results", () => {
    const value = trajectory();
    value.steps[1] = {
      ...step(value, 1),
      tool_calls: [
        {
          tool_call_id: "call-1",
          function_name: "lookup",
          arguments: {},
        },
        {
          tool_call_id: "call-1",
          function_name: "lookup",
          arguments: {},
        },
      ],
      observation: {
        results: [{ source_call_id: "missing-call", content: "missing" }],
      },
    };

    expect(
      collectAtifValidationDiagnostics(value).diagnostics.map(
        (entry) => entry.code,
      ),
    ).toEqual(["duplicate-tool-call", "unresolved-tool-result"]);
  });

  it("requires a tool result to reference a call on the same step", () => {
    const value = trajectory();
    value.steps[1] = {
      ...step(value, 1),
      tool_calls: [
        {
          tool_call_id: "call-1",
          function_name: "lookup",
          arguments: {},
        },
      ],
    };
    value.steps.push({
      step_id: 3,
      source: "agent",
      message: "Late result",
      observation: {
        results: [{ source_call_id: "call-1", content: "late" }],
      },
      llm_call_count: 1,
    });

    expect(
      collectAtifValidationDiagnostics(value).diagnostics.map(
        (entry) => entry.code,
      ),
    ).toEqual(["unresolved-tool-result"]);
  });

  it("requires embedded trajectory identity and resolvable embedded refs", () => {
    const value = trajectory();
    const child = trajectory();
    child.trajectory_id = undefined;
    value.subagent_trajectories = [child];
    value.steps[1] = {
      ...step(value, 1),
      observation: {
        results: [
          {
            content: "delegated",
            subagent_trajectory_ref: [{ trajectory_id: "missing-child" }],
          },
        ],
      },
    };

    expect(
      collectAtifValidationDiagnostics(value).diagnostics.map(
        (entry) => entry.code,
      ),
    ).toEqual([
      "unresolved-subagent-reference",
      "unresolved-subagent-reference",
    ]);
  });
});

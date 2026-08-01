import { describe, expect, it } from "vitest";
import { evaluateWhiteboxRecon } from "./evaluation";
import type { ReconSurface, WhiteboxReconResult } from "./types";

describe("evaluateWhiteboxRecon", () => {
  it("separates interface recall from application and provenance accuracy", () => {
    const expected = surface("api", "src/routes.ts", 10);
    const actual = surface("wrong-app", "src/other.ts", 20);
    const result = resultWith([actual]);

    const evaluation = evaluateWhiteboxRecon(result, {
      surfaces: [expected],
    });

    expect(evaluation.interface_recall).toBe(1);
    expect(evaluation.application_assignment_accuracy).toBe(0);
    expect(evaluation.source_file_accuracy).toBe(0);
  });

  it("reports exact operation and source matches", () => {
    const expected = surface("api", "src/routes.ts", 10);
    const evaluation = evaluateWhiteboxRecon(resultWith([expected]), {
      surfaces: [expected],
    });

    expect(evaluation).toEqual(
      expect.objectContaining({
        exact_matches: 1,
        interface_recall: 1,
        interface_precision: 1,
        application_assignment_accuracy: 1,
        source_file_accuracy: 1,
        source_line_accuracy: 1,
      }),
    );
  });
});

function surface(
  applicationId: string,
  sourceFile: string,
  sourceLine: number,
): ReconSurface {
  return {
    application_id: applicationId,
    type: "http",
    method: "GET",
    path_or_name: "/users/:id",
    source_file: sourceFile,
    source_line: sourceLine,
  };
}

function resultWith(surfaces: ReconSurface[]): WhiteboxReconResult {
  return {
    $schema: "whitebox-recon/v2",
    status: "complete",
    repository_root: "/repo",
    applications: [],
    surfaces,
    resources: [],
    unresolved: [],
    metrics: {
      duration_ms: 10,
      files_total: 1,
      files_relevant: 1,
      files_reviewed: 1,
      selectors_total: 1,
      selectors_completed: 1,
      shards_total: 1,
      shards_completed: 1,
      bundle_cache_hits: 0,
      candidates_total: 1,
      candidates_accepted: 1,
      candidates_persisted: 1,
      candidates_duplicate: 0,
      candidates_rejected: 0,
      candidates_unresolved: 0,
      records_accepted: 1,
      records_persisted: 1,
      agent_calls: 1,
      agent_failures: 0,
      tokens_in: 100,
      tokens_out: 20,
      estimated_tokens_in: 120,
    },
  };
}

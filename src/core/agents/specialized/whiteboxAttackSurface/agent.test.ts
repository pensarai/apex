import { describe, expect, it } from "vitest";
import {
  finalizeWhiteboxResult,
  WHITEBOX_FALLBACK_RESULT,
  WhiteboxSubmitValidationError,
} from "./agent";
import type { WhiteboxAttackSurfaceResult } from "./types";

describe("finalizeWhiteboxResult", () => {
  const captured: WhiteboxAttackSurfaceResult = {
    repoType: "monorepo",
    packageManager: "pnpm",
    apps: [],
    summary: {
      totalApps: 3,
      totalPages: 7,
      totalApiEndpoints: 22,
      totalPentestObjectives: 68,
    },
  };

  it("returns the captured result when submission validated", () => {
    // submitAttempted is irrelevant once a validated result exists.
    expect(finalizeWhiteboxResult(captured, true)).toBe(captured);
    expect(finalizeWhiteboxResult(captured, false)).toBe(captured);
  });

  it("fails loud when submit_results was called but never validated", () => {
    // The core defect: one bad field rejected the payload, capturedResult
    // stayed null, and the run used to report success with an empty result.
    expect(() => finalizeWhiteboxResult(null, true)).toThrow(
      WhiteboxSubmitValidationError,
    );
  });

  it("returns the empty fallback only when the model genuinely never submitted", () => {
    expect(finalizeWhiteboxResult(null, false)).toBe(WHITEBOX_FALLBACK_RESULT);
  });
});

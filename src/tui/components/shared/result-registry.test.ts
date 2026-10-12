import { describe, expect, it, vi } from "vitest";

// The real @opentui/core entrypoint loads tree-sitter .scm grammars, which
// node-environment vitest cannot parse; only StyledText is used at runtime
// on the paths under test.
vi.mock("@opentui/core", () => ({
  StyledText: class StyledText {},
}));
vi.mock("./syntax-highlight", () => ({
  highlightCode: () => null,
}));

import { getResultSummary } from "./result-registry";

describe("list_files result summary", () => {
  it("shows an exact count for untruncated listings", () => {
    const summary = getResultSummary(
      {
        success: true,
        error: "",
        files: ["a.txt", "b.txt", "c.txt"],
        directory: "/x",
        count: 3,
      },
      "list_files",
    );
    expect(summary?.text).toBe("3 files");
    expect(summary?.isError).toBe(false);
  });

  it("shows the exact total it paid for when a flat listing is truncated", () => {
    const summary = getResultSummary(
      {
        success: true,
        error: "Showing 500 of 600 entries",
        files: Array.from({ length: 20 }, (_, i) => `f${i}`),
        directory: "/x",
        count: 500,
        totalFound: 600,
        truncated: true,
      },
      "list_files",
    );
    expect(summary?.text).toBe("600 files");
    expect(summary?.fullText).toContain("(600 total)");
  });

  it("labels a recursive truncation's lower-bound count honestly", () => {
    const summary = getResultSummary(
      {
        success: true,
        error:
          "Listing truncated at 200 entries — narrow the directory or use grep",
        files: Array.from({ length: 20 }, (_, i) => `f${i}`),
        directory: "/x",
        count: 200,
        totalFound: 201,
        totalFoundLowerBound: true,
        truncated: true,
      },
      "list_files",
    );
    expect(summary?.text).toBe("at least 201 files");
    expect(summary?.fullText).toContain("(at least 201 total)");
  });

  it("never poses a bare truncation flag as an exact count", () => {
    const summary = getResultSummary(
      {
        success: true,
        error: "",
        files: Array.from({ length: 20 }, (_, i) => `f${i}`),
        directory: "/x",
        count: 200,
        truncated: true,
      },
      "list_files",
    );
    expect(summary?.text).toBe("200+ files");
  });

  it("keeps the failure path", () => {
    const summary = getResultSummary(
      { success: false, error: "EACCES: permission denied", files: [] },
      "list_files",
    );
    expect(summary?.isError).toBe(true);
    expect(summary?.text).toContain("EACCES");
  });
});

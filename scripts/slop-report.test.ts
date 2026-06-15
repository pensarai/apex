import { describe, expect, it } from "vitest";
import { COMMENT_MARKER, renderReport } from "./slop-report";

// ---------------------------------------------------------------------------
// renderReport turns a slop-scan `delta --json` payload into the Markdown body
// of an advisory PR comment. It is pure and must never throw — the workflow
// posts whatever it returns as a neutral, non-blocking check.
// ---------------------------------------------------------------------------

/** Build a single "added"/"worsened" change as slop-scan emits it. */
function change(
  status: "added" | "worsened" | "resolved",
  ruleId: string,
  severity: string,
  message: string,
  line?: number,
) {
  return {
    status,
    ruleId,
    head: { severity, message, primaryLocation: line ? { line } : undefined },
  };
}

describe("renderReport", () => {
  it("reports a clean PR when nothing was added or worsened", () => {
    const body = renderReport({
      summary: { addedCount: 0, worsenedCount: 0, resolvedCount: 0 },
    });
    expect(body).toContain(COMMENT_MARKER);
    expect(body).toContain("No new slop introduced");
    expect(body).not.toContain("| Location |");
    expect(body).not.toContain("🩹");
  });

  it("calls out resolved findings on an otherwise-clean PR", () => {
    const body = renderReport({
      summary: { addedCount: 0, worsenedCount: 0, resolvedCount: 3 },
    });
    expect(body).toContain("resolves 3");
  });

  it("renders a table of added/worsened findings with severity, location, and an actionable fix", () => {
    const body = renderReport({
      summary: { addedCount: 1, worsenedCount: 1, resolvedCount: 0 },
      paths: [
        {
          path: "src/a.ts",
          changes: [
            change(
              "added",
              "defensive.empty-catch",
              "strong",
              "Found 1 empty catch block",
              42,
            ),
          ],
        },
        {
          path: "src/b.ts",
          changes: [
            change(
              "worsened",
              "defensive.error-obscuring",
              "medium",
              "Obscures error",
              7,
            ),
          ],
        },
      ],
    });
    expect(body).toContain("**1** new");
    expect(body).toContain("**1** worsened");
    expect(body).toContain("🔴"); // strong
    expect(body).toContain("🟡"); // medium
    expect(body).toContain("`src/a.ts:42`");
    expect(body).toContain("`src/b.ts:7` _(worsened)_");
    expect(body).toContain("Suggested fix");
    // Actionable: each row carries a concrete remediation, not just the rule id.
    expect(body).toContain("Handle or log the error");
    expect(body).toContain("Preserve the original error");
  });

  it("uses the descriptive message and appends the boundary tag, with a default fix for unknown rules", () => {
    const body = renderReport({
      summary: { addedCount: 1, worsenedCount: 0, resolvedCount: 0 },
      paths: [
        {
          path: "src/a.ts",
          changes: [
            {
              status: "added",
              ruleId: "some.unknown-rule",
              head: {
                severity: "strong",
                message: "Found 1 empty catch block",
                evidence: ["line 42: empty catch, boundary=network"],
                primaryLocation: { line: 42 },
              },
            },
          ],
        },
      ],
    });
    expect(body).toContain("Found 1 empty catch block (boundary=network)"); // message + boundary
    expect(body).not.toContain("baseline="); // never surface the raw numeric evidence
    expect(body).toContain("tune the rule in `slop-scan.config.json`"); // default fix
  });

  it("renders only the message when evidence has no boundary tag (e.g. structural rules)", () => {
    const body = renderReport({
      summary: { addedCount: 1, worsenedCount: 0, resolvedCount: 0 },
      paths: [
        {
          path: "scripts",
          changes: [
            {
              status: "added",
              ruleId: "structure.directory-fanout-hotspot",
              head: {
                severity: "medium",
                message:
                  "Directory fan-out is a repo hotspot (16 files vs baseline 1.0)",
                evidence: ["baseline=1.00", "threshold=6", "fileCount=16"],
              },
            },
          ],
        },
      ],
    });
    expect(body).toContain(
      "Directory fan-out is a repo hotspot (16 files vs baseline 1.0)",
    );
    expect(body).not.toContain("baseline=1.00");
  });

  it("omits the 'new' segment for a worsened-only delta (no '0 new')", () => {
    const body = renderReport({
      summary: { addedCount: 0, worsenedCount: 1, resolvedCount: 0 },
      paths: [
        {
          path: "src/a.ts",
          changes: [
            change(
              "worsened",
              "defensive.empty-catch",
              "strong",
              "Found 2 empty catch blocks",
              5,
            ),
          ],
        },
      ],
    });
    expect(body).toContain("**1** worsened finding");
    expect(body).not.toContain("new");
  });

  it("counts added/worsened from the rendered rows, not summary (no header-only table)", () => {
    // summary claims a finding, but no matching path change exists → treat as clean, no empty table.
    const body = renderReport({
      summary: { addedCount: 1, worsenedCount: 0, resolvedCount: 0 },
      paths: [],
    });
    expect(body).toContain("No new slop introduced");
    expect(body).not.toContain("| Location |");
  });

  it("ignores resolved/unchanged occurrences in the table", () => {
    const body = renderReport({
      summary: { addedCount: 0, worsenedCount: 0, resolvedCount: 1 },
      paths: [
        {
          path: "src/a.ts",
          changes: [
            change("resolved", "defensive.empty-catch", "strong", "gone", 1),
          ],
        },
      ],
    });
    // resolved-only with no adds/worsens takes the clean path, not the table.
    expect(body).not.toContain("| Location |");
    expect(body).toContain("resolves 1");
  });

  it("escapes pipes and collapses newlines so the table cannot break", () => {
    const body = renderReport({
      summary: { addedCount: 1, worsenedCount: 0, resolvedCount: 0 },
      paths: [
        {
          path: "src/a.ts",
          changes: [
            change("added", "x.rule", "strong", "a | b\nsecond line", 1),
          ],
        },
      ],
    });
    const row = body.split("\n").find((l) => l.includes("`src/a.ts:1`")) ?? "";
    expect(row).toContain("a \\| b second line"); // pipe escaped, newline collapsed
    expect(row).not.toMatch(/\n/);
    // The escaped pipe is the only literal `|`-with-backslash; the row's
    // own column separators stay intact.
    expect(row.startsWith("|")).toBe(true);
  });

  it("falls back gracefully when the location has no line number", () => {
    const body = renderReport({
      summary: { addedCount: 1, worsenedCount: 0, resolvedCount: 0 },
      paths: [
        {
          path: "src/dir",
          changes: [change("added", "structure.x", "medium", "dir issue")],
        },
      ],
    });
    expect(body).toContain("`src/dir`");
    expect(body).not.toContain("`src/dir:`");
  });

  it("tolerates a missing summary without throwing", () => {
    expect(() => renderReport({})).not.toThrow();
    expect(renderReport({})).toContain("No new slop introduced");
  });
});

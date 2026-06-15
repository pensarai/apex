#!/usr/bin/env bun
// Render a slop-scan `delta --json` report as a Markdown PR comment body.
// Usage: `bun run scripts/slop-report.ts <delta.json>`
import { readFileSync } from "node:fs";

/** Stable marker so the workflow can find-and-update its own comment. */
export const COMMENT_MARKER = "<!-- slop-scan-report -->";

interface OccurrenceSide {
  message?: string;
  severity?: string;
  evidence?: string[];
  primaryLocation?: { line?: number };
}
interface Occurrence {
  status: "added" | "worsened" | "resolved" | "improved" | "unchanged";
  ruleId: string;
  severity?: string;
  head?: OccurrenceSide | null;
  base?: OccurrenceSide | null;
}
interface DeltaPath {
  path: string;
  changes?: Occurrence[];
}
interface Delta {
  summary?: {
    addedCount?: number;
    worsenedCount?: number;
    resolvedCount?: number;
    improvedCount?: number;
    headFindingCount?: number;
  };
  paths?: DeltaPath[];
}

const SEVERITY_ICON: Record<string, string> = {
  strong: "🔴",
  medium: "🟡",
  weak: "⚪",
};

// Concrete remediation per rule — a finding is only useful if it says what to do.
const FIX_HINTS: Record<string, string> = {
  "defensive.empty-catch":
    "Handle or log the error, or comment why it's safe to swallow.",
  "defensive.error-obscuring":
    "Preserve the original error (e.g. `cause`) instead of replacing it.",
  "defensive.error-swallowing":
    "Don't log-and-continue if the caller needs to know it failed.",
  "defensive.async-noise":
    "Await the promise or handle rejection; avoid fire-and-forget.",
  "structure.pass-through-wrappers":
    "Inline the wrapper or give it behavior of its own.",
  "structure.duplicate-function-signatures":
    "Extract a shared helper/type for the repeated signature.",
  "structure.barrel-density":
    "Drop the barrel; import the underlying files directly.",
  "structure.directory-fanout-hotspot":
    "Group related files into a cohesive submodule.",
  "structure.over-fragmentation": "Consolidate the over-split modules.",
  "comments.placeholder-comments":
    "Remove the placeholder comment or implement what it describes.",
  "tests.duplicate-mock-setup":
    "Extract the repeated mock/setup into a shared fixture.",
};
const DEFAULT_FIX =
  "Address it, or tune the rule in `slop-scan.config.json` if it's noise.";

/** Newlines break table rows and pipes break columns — neutralize both. */
const cell = (s: string) => s.replace(/\s*\n\s*/g, " ").replace(/\|/g, "\\|");

/** The message is the human-readable summary; append the boundary tag from evidence when present (it tells you what kind of catch/edge a defensive finding guards). */
function describe(side?: OccurrenceSide | null): string {
  const message = side?.message?.trim();
  const boundary = side?.evidence?.join(" ").match(/boundary=\S+/)?.[0];
  if (message && boundary) return `${message} (${boundary})`;
  return message || side?.evidence?.[0] || "issue";
}

export function renderReport(delta: Delta): string {
  const s = delta.summary ?? {};
  const added = s.addedCount ?? 0;
  const worsened = s.worsenedCount ?? 0;
  const resolved = s.resolvedCount ?? 0;

  const lines: string[] = [COMMENT_MARKER, "## Slop Scan", ""];

  if (added === 0 && worsened === 0) {
    lines.push(
      resolved > 0
        ? `No new slop introduced — and this PR resolves ${resolved} existing finding${resolved === 1 ? "" : "s"}.`
        : "No new slop introduced by this PR.",
    );
    return lines.join("\n");
  }

  const summaryBits = [`**${added}** new`];
  if (worsened > 0) summaryBits.push(`**${worsened}** worsened`);
  if (resolved > 0) summaryBits.push(`${resolved} resolved`);
  lines.push(
    `${summaryBits.join(" · ")} finding${added + worsened === 1 ? "" : "s"} vs. the base branch.`,
    "",
  );
  lines.push("| | Location | Issue | Suggested fix |", "| - | - | - | - |");

  for (const p of delta.paths ?? []) {
    for (const c of p.changes ?? []) {
      if (c.status !== "added" && c.status !== "worsened") continue;
      const severity = c.head?.severity ?? c.base?.severity ?? c.severity ?? "";
      const icon = SEVERITY_ICON[severity] ?? "•";
      const line = c.head?.primaryLocation?.line;
      const loc = line ? `\`${p.path}:${line}\`` : `\`${p.path}\``;
      const tag = c.status === "worsened" ? " _(worsened)_" : "";
      const issue = `${cell(describe(c.head))} (\`${c.ruleId}\`)`;
      const fix = cell(FIX_HINTS[c.ruleId] ?? DEFAULT_FIX);
      lines.push(`| ${icon} | ${loc}${tag} | ${issue} | ${fix} |`);
    }
  }

  return lines.join("\n");
}

// Run directly (not when imported by a test).
if (import.meta.main) {
  const path = process.argv[2];
  if (!path) {
    console.error("usage: bun run scripts/slop-report.ts <delta.json>");
    process.exit(2);
  }
  let delta: Delta;
  try {
    delta = JSON.parse(readFileSync(path, "utf8")) as Delta;
  } catch (err) {
    // Advisory: bad/missing input must never fail CI — degrade and exit 0.
    const reason = err instanceof Error ? err.message : String(err);
    process.stdout.write(
      `${COMMENT_MARKER}\n## Slop Scan\n\n⚠️ slop-scan could not produce a delta report (${reason}). No slop verdict for this PR.\n`,
    );
    process.exit(0);
  }
  process.stdout.write(`${renderReport(delta)}\n`);
}

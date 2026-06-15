#!/usr/bin/env bun
// Render a slop-scan `delta --json` report as a Markdown PR comment body.
// Usage: `bun run scripts/slop-report.ts <delta.json>`
import { readFileSync } from "node:fs";

/** Stable marker so the workflow can find-and-update its own comment. */
export const COMMENT_MARKER = "<!-- slop-scan-report -->";

interface OccurrenceSide {
  message?: string;
  severity?: string;
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

export function renderReport(delta: Delta): string {
  const s = delta.summary ?? {};
  const added = s.addedCount ?? 0;
  const worsened = s.worsenedCount ?? 0;
  const resolved = s.resolvedCount ?? 0;

  const lines: string[] = [COMMENT_MARKER, "## 🩹 Slop Scan", ""];

  if (added === 0 && worsened === 0) {
    lines.push(
      resolved > 0
        ? `✅ No new slop introduced — and this PR **resolves ${resolved}** existing finding${resolved === 1 ? "" : "s"}. Nice.`
        : "✅ No new slop introduced by this PR.",
    );
    lines.push("", "_Advisory only — this check never blocks merge._");
    return lines.join("\n");
  }

  const summaryBits = [`**${added}** new`];
  if (worsened > 0) summaryBits.push(`**${worsened}** worsened`);
  if (resolved > 0) summaryBits.push(`${resolved} resolved`);
  lines.push(
    `${summaryBits.join(" · ")} finding${added + worsened === 1 ? "" : "s"} vs. the base branch.`,
    "",
  );
  lines.push("| | Location | Rule | Detail |", "| - | - | - | - |");

  for (const p of delta.paths ?? []) {
    for (const c of p.changes ?? []) {
      if (c.status !== "added" && c.status !== "worsened") continue;
      const severity = c.head?.severity ?? c.base?.severity ?? c.severity ?? "";
      const icon = SEVERITY_ICON[severity] ?? "•";
      const line = c.head?.primaryLocation?.line;
      const loc = line ? `\`${p.path}:${line}\`` : `\`${p.path}\``;
      const tag = c.status === "worsened" ? " _(worsened)_" : "";
      // Collapse newlines (would break the table row) and escape pipes.
      const detail = (c.head?.message ?? "")
        .replace(/\s*\n\s*/g, " ")
        .replace(/\|/g, "\\|");
      lines.push(`| ${icon} | ${loc}${tag} | \`${c.ruleId}\` | ${detail} |`);
    }
  }

  lines.push(
    "",
    "_Advisory only — this check never blocks merge. If a finding is a false positive or an accepted pattern, you can ignore it; persistently noisy rules will be tuned out in `slop-scan.config.json`._",
  );
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
      `${COMMENT_MARKER}\n## 🩹 Slop Scan\n\n⚠️ slop-scan did not produce a usable delta report (${reason}). No slop verdict for this PR.\n\n_Advisory only — this check never blocks merge._\n`,
    );
    process.exit(0);
  }
  process.stdout.write(`${renderReport(delta)}\n`);
}

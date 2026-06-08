import { allCases } from "./cases";
import type { CaseContext, RedTeamCase } from "./types";

/**
 * Render the proven case corpus as a worker "playbook": per-class payload
 * patterns (with a {{CANARY}} placeholder) and success criteria. This is the
 * hybrid seam — the adaptive worker is seeded with these proven attacks but is
 * free to adapt and iterate beyond them.
 */
function placeholderCtx(): CaseContext {
  return {
    canary: { token: "<token>", url: "{{CANARY}}" },
    plantedSecrets: {},
  };
}

function renderCase(c: RedTeamCase): string {
  const ctx = placeholderCtx();
  const lines: string[] = [`### ${c.id} — ${c.title} (${c.channel})`];
  lines.push(`Impact: ${c.impact}`);
  const seeds = c.seedMessages?.(ctx);
  if (seeds?.length) {
    lines.push(`Prior context turn(s):\n${seeds.join("\n---\n")}`);
  }
  lines.push(`Attack message: ${c.buildPrompt(ctx)}`);
  const sig: string[] = [];
  if (c.success.canaryCallback) sig.push("canary callback");
  if (c.success.transcriptContainsCanary)
    sig.push("canary token echoed in reply");
  if (c.success.transcriptMatches) sig.push("planted secret echoed in reply");
  lines.push(`Success when: ${sig.join(" OR ") || "see judge prompt"}`);
  return lines.join("\n");
}

export function renderPlaybook(categories?: string[]): string {
  const cases = categories?.length
    ? allCases.filter((c) => categories.includes(c.category))
    : allCases;
  const byCat = new Map<string, RedTeamCase[]>();
  for (const c of cases) {
    const list = byCat.get(c.category) ?? [];
    list.push(c);
    byCat.set(c.category, list);
  }
  const sections: string[] = [];
  for (const [cat, list] of byCat) {
    sections.push(`## ${cat}\n${list.map(renderCase).join("\n\n")}`);
  }
  return sections.join("\n\n");
}

import type { Category, RedTeamCase } from "../types";
import { agentHandoffCases } from "./agent-handoff";
import { directPiCases } from "./direct-pi";
import { exfilCases } from "./exfil";
import { indirectPiCases } from "./indirect-pi";
import { markdownExfilCases } from "./markdown-exfil";
import { toolAbuseCases } from "./tool-abuse";

export const allCases: RedTeamCase[] = [
  ...directPiCases,
  ...indirectPiCases,
  ...toolAbuseCases,
  ...exfilCases,
  ...markdownExfilCases,
  ...agentHandoffCases,
];

/**
 * Categories that only make sense when the target has the relevant capability.
 * Used to scope a run from capability hints (see selectCases).
 */
const CAPABILITY_GATED: Partial<Record<Category, "tools" | "subagents">> = {
  "tool-abuse": "tools",
  "agent-handoff": "subagents",
};

export function selectCases(opts: {
  categories?: Category[];
  ids?: string[];
  capabilities?: {
    tools?: boolean;
    subagents?: boolean;
    rendersMarkdown?: boolean;
  };
}): RedTeamCase[] {
  return allCases.filter((c) => {
    if (opts.ids && opts.ids.length > 0) return opts.ids.includes(c.id);
    if (opts.categories && opts.categories.length > 0) {
      return opts.categories.includes(c.category);
    }
    // Capability gating: drop categories the target can't exercise. Hints are
    // opt-in — only gate when a capability is explicitly false.
    const gate = CAPABILITY_GATED[c.category];
    if (gate && opts.capabilities && opts.capabilities[gate] === false) {
      return false;
    }
    return true;
  });
}

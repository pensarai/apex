import type { BuiltInSkill } from "../types";

/**
 * Build the runtime prompt for the `/triage` skill.
 *
 * Triage is workflow-driven (not LLM-driven) — the actual pipeline runs
 * outside the agent in {@link import("../../workflows/triage").runTriageWorkflow}.
 * This prompt is what the agent sees if a user invokes the skill through
 * the standard skills loop; it directs the agent to delegate to the
 * workflow tool rather than improvise.
 */
export function buildTriagePrompt(opts: {
  reportPath: string;
  target: string;
  outputDir: string;
  cwd: string;
  skillContent: string;
}): string {
  const ctx = [
    `Report file: ${opts.reportPath}`,
    `Live target: ${opts.target}`,
    `Output directory: ${opts.outputDir}`,
    `Codebase / context root: ${opts.cwd}`,
  ].join("\n");

  return `<skill name="triage" target="${opts.target}">\n${ctx}\n\n${opts.skillContent}\n</skill>`;
}

export const triageSkill: BuiltInSkill = {
  slug: "triage",
  manifest: {
    name: "Bug Bounty Triage",
    description:
      "Triage an inbound bug bounty report — scope, dedup, live PoC re-verification, CVSS recalibration, and a remediation draft",
    tags: ["security", "appsec", "bug-bounty", "triage"],
    inputs: [
      {
        name: "report",
        description: "Path to the inbound report file (markdown/JSON/text)",
        required: true,
      },
      {
        name: "target",
        description: "Live target URL for PoC re-verification",
        required: true,
      },
      {
        name: "source",
        description:
          "Report source platform: 'hackerone' to activate the deterministic H1 JSON fast-path, or 'auto' to detect (default: auto)",
        required: false,
      },
      {
        name: "output",
        description:
          "Output directory for triage.md + decision.json (default: ./bounty-triage/<slug>)",
        required: false,
      },
      {
        name: "cwd",
        description: "Repository root for program-context files and remediation drafting (default: process cwd)",
        required: false,
      },
    ],
    outputs: [
      { name: "triage.md", description: "Human-readable triage report" },
      { name: "decision.json", description: "Schema-validated TriageResult" },
    ],
  },
  instructions: `You are the orchestrator for an inbound bug bounty triage. You operate fully autonomously — do not ask the user for input or permission.

The runtime context above gives you a report file, a live target, an output directory, and a codebase root.

Your job is to run the triage workflow end-to-end. The workflow performs, in order:

1. **Parse** the inbound report into structured fields.
2. **Load program context** from \`<cwd>/.apex/bug-bounty/scope.md\`, \`engagement.md\`, \`business-context.md\`, and the latest threat model under \`<cwd>/.apex/threat-models/\`. Missing files are non-fatal.
3. **Scope check** — host-level against the session's allowedHosts, then policy-level against scope.md and engagement.md.
4. **Duplicate check** — against the configured findings registry. Returns a duplicate match-type (\`exact\`, \`application-wide\`, or \`none\`).
5. **Live PoC re-verification** — attempt the reporter's PoC against the live target using only HTTP and shell commands. All traffic is bounded by the session's scope constraints.
6. **CVSS recalibration** — score the reproduced finding with CVSS 4.0.
7. **Threat-model alignment** — map the reproduced finding onto the threat model and detect any explicit accepted-risk declaration.
8. **Decide** — accept / reject / needs-info with one of the canonical reasons (\`confirmed\`, \`out-of-scope\`, \`duplicate\`, \`unreproducible\`, \`informational\`, \`business-accepted-risk\`, \`missing-info\`).
9. **Remediation draft** (only when accepted) — produce a PR title, PR description, and a list of files-to-change via the patching agent.
10. **Write outputs** — \`triage.md\` (human-readable, with the remediation draft embedded as a section) and \`decision.json\` (schema-validated TriageResult).

# Output expectations

- The triage markdown is the human-readable artifact. The decision JSON is the machine-readable one.
- Do not write any other files in the output directory.
- The remediation draft must live inside \`triage.md\` as a "Suggested remediation" section — do NOT write a separate diff or patch file.

# Rules

- Never declare \`accept\` without reproduction evidence. If verification did not reproduce, the only valid outcomes are \`reject:unreproducible\` or \`needs-info\`.
- Quote the failing policy line verbatim when rejecting as out-of-scope.
- Do not silently degrade: if a step fails for an infrastructure reason (e.g. target unreachable), surface that in the decision rationale rather than producing a confident \`reject\`.
`,
};

import type { BuiltInSkill } from "../types";

export const whiteboxReconSkill: BuiltInSkill = {
  slug: "whitebox-recon",
  manifest: {
    name: "Whitebox Recon",
    description:
      "Profile a source repository into applications, interfaces, resources, and infrastructure identity",
    tags: ["security", "reconnaissance", "source-code"],
    inputs: [
      {
        name: "cwd",
        description: "Repository path; defaults to the working directory",
        required: false,
      },
      {
        name: "workers",
        description: "Maximum concurrent map workers",
        required: false,
      },
    ],
  },
  instructions: `Run source-code attack-surface reconnaissance. This is inventory and mapping only, not penetration testing.

Call the \`run_whitebox_recon\` tool exactly once with:
- \`cwd\`: the cwd value from runtime context when present; otherwise the Working directory
- \`maxConcurrentWorkers\`: the workers value converted to a number when present; otherwise omit it
- \`toolCallDescription\`: "Profiling repository attack surface"

The tool owns the complete workflow: repository census, deterministic selector execution, bounded evidence-bundle analysis, canonical reconciliation, artifact persistence, and completeness verification. Do not manually enumerate the repository or invoke legacy white-box, attack-surface, Surface, pentest, or subagent tools before or after it.

After it returns, report:
1. Whether status is complete or incomplete
2. Application, interface, resource, and unresolved counts
3. Files scanned versus relevant files
4. The result.json path

If status is incomplete, state that the result is partial and direct the operator to unresolved entries. Do not continue into vulnerability analysis or pentesting.`,
};

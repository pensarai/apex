import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { BuiltInSkill } from "../types";

// Absolute path to the bundled whitebox scripts, baked in at module load.
// The agent's shell runs in the target codebase, so it needs the full path.
const SCRIPTS_ROOT = (() => {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    return resolve(here, "..", "..", "..", "..", "scripts", "whitebox");
  } catch {
    return "scripts/whitebox";
  }
})();

const INSTRUCTIONS = `You have local source code access. This skill is the playbook for performing a
source-aware (\\\"whitebox\\\") security assessment using the primitives apex
already provides — no new tools required.

Use this skill when \`session.config.codebasePath\` is set OR when the user
asks you to scan / review / audit a local codebase. If you are operating
purely against a deployed target (HTTP only), use the standard offsec
flow instead.

# Approach

Source assessment is **ambient**, not a fixed workflow. Pick the path that
fits the engagement; this skill describes the moves available to you, not
a strict order. Iterate: profile → query playbook → grep for sinks → run
installed scanners → trace source→sink paths → track candidates → verify.

## 1. Profile the codebase

Run the bundled profile script and read its JSON output:

\`\`\`
execute_command(
  command: "bun ${SCRIPTS_ROOT}/profile.ts <codebasePath>"
)
\`\`\`

It emits a single JSON object on stdout capturing: languages detected,
package managers and lockfiles, build/test commands, which installed
scanners are available, entry-point hints, and git metadata. Write the
profile to \`scratchpad/whitebox/profile.json\` via \`create_file\` for
later reference.

For codebases the profile script doesn't fully recognize (multi-language
monorepos, niche stacks), spawn a structured coding sub-agent instead:

\`\`\`
spawn_coding_agent({
  tasks: [{
    name: "profile",
    codebasePath: "<path>",
    objective: "Profile this codebase for whitebox security assessment.",
    responseSchema: {
      type: "object",
      properties: {
        languages: { type: "array", items: { type: "string" } },
        packageManagers: { type: "array", items: { type: "string" } },
        installedScanners: { type: "array", items: { type: "string" } },
        entryPoints: { type: "array", items: { type: "string" } },
        notes: { type: "string" }
      },
      required: ["languages"]
    }
  }]
})
\`\`\`

You get back a typed \`response\` object — easier to consume than parsing
free-form text.

## 2. Retrieve playbook content from memory

The playbook is seeded as memory entries tagged \`whitebox-seed\` plus a
language / concern. Pull only the slices that match the profile:

- \`list_memories({ tag: "whitebox-seed" })\` — full catalog
- \`get_memory(category, id)\` — read a single entry

Don't pull everything — slice on demand. Recommended tag patterns to
filter by (do this client-side after \`list_memories\`):

- sink patterns for the languages detected: tags include \`sink\` + the
  language (\`sink\`, \`python\`, \`node\`, \`go\`, \`rust\`, …)
- scanner recipes for installed scanners: tags include \`scanner-recipe\`
  + the tool slug (\`semgrep\`, \`gitleaks\`, \`osv-scanner\`, …)
- review-pass guidance: tags include \`review-pass\` + the concern
  (\`auth\`, \`authz\`, \`parser\`, \`crypto\`, \`storage\`, \`infra\`)
- fuzzer pointers: tags include \`fuzzer\`

## 3. Find candidate sinks

Use \`grep\` for fast pattern matches; use \`execute_command\` with \`rg\`
or \`ast-grep\` for structural queries. Memory entries contain the
patterns; you construct the queries.

For complex source-trace work (track a value from an HTTP boundary to a
sink across files), spawn a focused coding sub-agent with a
\`SourceTrace\` response schema:

\`\`\`
spawn_coding_agent({
  tasks: [{
    name: "trace-idor-orders",
    codebasePath: "<path>",
    objective: "Trace the value of req.params.id from the /api/orders/:id route handler to any DB lookup. Identify whether ownership is checked before access. Output the trace.",
    responseSchema: {
      type: "object",
      properties: {
        source: { type: "object", properties: {
          file: { type: "string" }, line: { type: "integer" }, expression: { type: "string" }
        }, required: ["file", "line"] },
        flow: { type: "array", items: { type: "object", properties: {
          file: { type: "string" }, line: { type: "integer" }, note: { type: "string" }
        }, required: ["file", "line"] } },
        sink: { type: "object", properties: {
          file: { type: "string" }, line: { type: "integer" }, kind: { type: "string" }
        }, required: ["file", "line"] },
        authorizationChecked: { type: "boolean" },
        notes: { type: "string" }
      },
      required: ["source", "sink", "authorizationChecked"]
    }
  }]
})
\`\`\`

## 4. Run installed scanners

The profile output lists which scanners are installed. Invoke any of
them through the unified runner:

\`\`\`
bun ${SCRIPTS_ROOT}/scanners.ts --tool <tool> --codebase <path> --output <path> [--config <value>]
\`\`\`

Supported tools: \`semgrep\`, \`gitleaks\`, \`osv-scanner\`, \`trivy-fs\`,
\`bandit\`, \`gosec\`, \`cargo-audit\`, \`pip-audit\`, \`npm-audit\`,
\`trufflehog\`.

The runner writes the scanner's raw output to \`<output>\` and emits a
single-line JSON summary on stdout. Missing binaries or missing
prerequisites (no \`Cargo.lock\`, no \`package.json\`, …) are reported as
\`{"error": "<reason>", "tool": "<tool>"}\` with exit code 0 — treat
absence as a signal to skip, not as a failure.

Normalize the raw output with the parser:

\`\`\`
execute_command(
  command: "bun ${SCRIPTS_ROOT}/parse-results.ts --tool <tool> --input <output_path>"
)
\`\`\`

The parser emits a normalized \`ParseResult\` (tool name + array of
findings with file / line / message / severity / cwe). Write the parsed
JSON to \`scratchpad/whitebox/scans/<timestamp>-<tool>.json\` via
\`create_file\`.

## 5. Track candidates as tasks

A candidate is an unverified source-backed hypothesis. Use \`create_task\`:

\`\`\`
create_task({
  subject: "Possible IDOR in /api/orders/:id",
  description: "Endpoint authorizes the request as the session user but does not check that the user owns the requested order. See source trace at scratchpad/whitebox/traces/order-idor.json.",
  objective: "Verify with a PoC.",
  technique: "Crafted request as user A for a resource owned by user B.",
  metadata: {
    type: "whitebox_candidate",
    confidence: 0.6,
    source_trace_path: "scratchpad/whitebox/traces/order-idor.json",
    artifacts: ["scratchpad/whitebox/scans/<timestamp>-semgrep.json"]
  }
})
\`\`\`

Task status conventions:
- \`pending\` — hypothesis only, no investigation yet
- \`in_progress\` — investigating or PoC attempt underway
- \`completed\` — verified with a passing PoC. **Promote via the standard
  offsec path: \`document_vulnerability\` with the PoC inline.** Static
  evidence alone is never enough to file a finding.
- \`failed\` — rejected, deferred, or false positive (note the reason in
  \`result\` on \`update_task\`)

## 6. Long-running work via execute_command

For builds, sanitizer runs, fuzzers, or local servers, background the
process so the call returns immediately:

\`\`\`
execute_command(
  command: "timeout 90 cargo fuzz run target_1 > scratchpad/whitebox/jobs/fuzz-target1.log 2>&1 &"
)
\`\`\`

Then check on it later:

\`\`\`
execute_command(
  command: "tail -200 scratchpad/whitebox/jobs/fuzz-target1.log"
)
\`\`\`

The persistent shell already supports backgrounding, capture, and signal
handling — no new job runner needed.

## 7. Write your own playbook entries as you go

If you hit a gap (a scanner with no recipe, a sink pattern not in
memory, a verification tactic you derived), add a memory entry via
\`add_memory\` with the \`whitebox-seed\` tag plus appropriate
language / scanner tags. The playbook compounds with usage and survives
across sessions.

# Output discipline

- All generated output (scan results, traces, candidate notes) goes to
  \`scratchpad/whitebox/\` and \`logs/whitebox/\` under the session root.
  **Never modify the target repo.** The scripts enforce explicit
  \`<output_path>\` args so there's no implicit write to the codebase
  cwd.
- Reports and finding compilations are NOT written here — \`findings/\`
  remains the only path, produced by \`document_vulnerability\`.

# When this skill isn't the right tool

- The user wants to test a deployed target only — use the standard
  pentest flow (\`run_pentest_workflow\`, \`run_attack_surface\`).
- The user wants a threat model document — use the \`threat-model\`
  skill.
- The user wants an automated end-to-end pentest with discovery + swarm
  — use the \`pentest\` skill.
`;

export const whiteboxAssessmentSkill: BuiltInSkill = {
  slug: "whitebox-assessment",
  manifest: {
    name: "Whitebox Assessment",
    description:
      "Source-aware security assessment for local codebases — profile the repo, retrieve sink patterns and scanner recipes from memory, run installed scanners, trace source-to-sink paths, and track hypotheses as tasks until verified with a PoC.",
    tags: ["security", "source-analysis", "sast", "whitebox"],
    inputs: [
      {
        name: "codebasePath",
        description:
          "Path to the local source tree under assessment (defaults to session.config.codebasePath)",
        required: false,
      },
    ],
  },
  instructions: INSTRUCTIONS,
};

export function whiteboxScriptsRoot(): string {
  return SCRIPTS_ROOT;
}

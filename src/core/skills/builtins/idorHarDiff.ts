import type { BuiltInSkill } from "../types";

export const idorHarDiffSkill: BuiltInSkill = {
  slug: "idor-har-diff",
  manifest: {
    name: "IDOR HAR Diff",
    description:
      "Capture two authenticated browser flows and compare their HARs to find IDOR and broken authorization candidates",
    tags: ["security", "authz", "idor"],
    inputs: [
      {
        name: "credentialIdA",
        description: "First account credential ID or account label",
        required: true,
      },
      {
        name: "credentialIdB",
        description: "Second account credential ID or account label",
        required: true,
      },
      {
        name: "seedUrls",
        description:
          "Optional URLs or browser flow to capture under both accounts",
        required: false,
      },
    ],
  },
  instructions: `# IDOR HAR Diff

Use this skill for IDOR / broken authorization testing when two comparable accounts are available. Captured HARs keep in-scope auth headers so candidates can be replayed.

## Workflow

1. Capture the same flow as Account A with \`start_har_capture\` / \`stop_har_capture\`; keep the returned \`path\`.
2. Capture the same flow as Account B; keep the returned \`path\`.
3. Compare both files with \`har_diff\`.
4. Replay high-suspicion entries with \`har_replay\`. A diff alone is not a vulnerability; document only confirmed cross-account access.

## How to read the diff

- \`same-response\`: most suspicious when user-specific data is present.
- \`different-but-200\`: inspect IDs, owners, tenant IDs, and object counts.
- \`403-vs-200\`: often correct authorization; useful for locating the boundary.
- \`unique-to-a\` / \`unique-to-b\`: often role/UI driven; inspect before replay.

## Rules

- Do not report IDOR if the endpoint is unauthenticated for everyone. That is missing authentication, not IDOR.
- Avoid replaying out-of-scope hosts.
- Do not call destructive methods unless necessary.
- Prefer confirming read-only access first (\`GET\` / safe \`POST\`) before attempting mutations.
`,
};

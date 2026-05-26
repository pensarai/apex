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

Use this skill when the operator asks for IDOR / broken authorization testing, or when two comparable user accounts are available and you need to compare what each account can see.

This skill encodes a known pentester workflow: perform the same browser flow as Account A and Account B, compare the captured traffic, then actively confirm any cross-account access with replay. The HARs intentionally include \`Authorization\`, \`Cookie\`, and \`Set-Cookie\` values for in-scope hosts because replay and session-management analysis need them.

## Workflow

1. Start Account A capture:
   - Call \`start_har_capture\` with a descriptive name such as \`account-a-profile\`.
   - Log in or switch to Account A.
   - Navigate through the requested flow or seed URLs.
   - Call \`stop_har_capture\` and keep the returned \`path\`.

2. Start Account B capture:
   - Call \`start_har_capture\` with a descriptive name such as \`account-b-profile\`.
   - Log out / switch accounts if needed.
   - Perform the same flow as Account B.
   - Call \`stop_har_capture\` and keep the returned \`path\`.

3. Compare the HARs:
   - Call \`har_diff\` with \`accountAHarPath\` and \`accountBHarPath\`.
   - Keep the returned \`path\` to the generated JSON report.

4. Confirm candidates:
   - Review the \`har_diff\` candidates.
   - For each high-suspicion candidate, call \`har_replay\` against the relevant captured entry.
   - A diff alone is not a vulnerability. Only document a finding after replay confirms Account B can access Account A's resource or data.

## How to read the diff

- \`same-response\`: both accounts received very similar 2xx responses for the same request shape. Investigate when the response contains user-specific data.
- \`different-but-200\`: both accounts received 2xx, but the bodies differ. Often expected; inspect IDs, owner fields, tenant IDs, and object counts.
- \`403-vs-200\`: one account is blocked and the other succeeds. This is often correct authorization, but can reveal which request carries the authorization boundary.
- \`unique-to-a\` / \`unique-to-b\`: one flow made a request the other never made. Often UI/role driven; inspect before replay.

## Rules

- Do not report IDOR if the endpoint is unauthenticated for everyone. That is missing authentication, not IDOR.
- Do not replay out-of-scope hosts. The \`har_replay\` tool enforces scope, but you should avoid selecting those candidates.
- Do not call destructive methods unless necessary. \`har_replay\` will require operator approval for \`DELETE\`, \`PUT\`, \`PATCH\`, credential swaps, and auth-header overrides.
- Prefer confirming read-only access first (\`GET\` / safe \`POST\`) before attempting mutations.
`,
};

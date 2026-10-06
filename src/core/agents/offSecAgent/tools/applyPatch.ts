import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ApplyPatchResult } from "./applyPatchImpl";
import type { ToolContext } from "./types";

export type {
  ApplyPatchResult,
  FilePatchResult,
  FilePatchStatus,
} from "./applyPatchImpl";
export {
  duplicateTargetKey,
  parseUnifiedDiff,
} from "./applyPatchImpl";

const applyPatchInputSchema = z.object({
  patch: z
    .string()
    .describe(
      "Unified diff to apply. May contain one or more file hunks (---/+++/@@). Paths are relative to the agent working directory unless absolute.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Apply parameterized-query fix across auth handlers')",
    ),
});

export function applyPatch(ctx: ToolContext) {
  return tool({
    description: `Apply a unified diff patch to one or more files.

Use this for multi-hunk or multi-file edits. For a single small string replace,
prefer update_file.

The entire patch is validated against current file contents before anything is
changed: if any file's context does not match, a create target already exists,
or a prepared result violates the text/size limits, nothing is written. Context
must match at exactly one position in the file — matches at multiple positions
are rejected; add more context lines to disambiguate. Commits are conditional —
if a file changed since the preflight read, that file fails and later files are
left unapplied (already-applied files stay applied; there is no rollback). Each
file gets a receipt: applied, failed, or unapplied.

Create files with a "--- /dev/null" header; delete with "+++ /dev/null" (the
hunks must cover the whole file; symlink deletion patches are rejected).
Renames, copies, mode changes, and binary
patches are rejected. Final newlines, BOMs, and CRLF line endings are preserved;
an LF patch applied to a CRLF file is adapted and reported in the receipt.
Paths resolve under the agent working directory (or file workspace when scoped).`,
    inputSchema: applyPatchInputSchema,
    execute: async ({ patch }): Promise<ApplyPatchResult> => {
      const { fs } = resolveBackends(ctx);
      return fs.applyPatch(patch);
    },
  });
}

import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { GrepResult } from "./grepImpl";
import { MAX_OUTPUT_CHARS } from "./grepImpl";
import { toolOutputForModel } from "./toolOutput";
import type { ToolContext } from "./types";

export type { GrepFlagValidation, GrepResult } from "./grepImpl";
export { validateGrepFlags } from "./grepImpl";

const grepInputSchema = z.object({
  pattern: z.string().describe("The pattern to search for"),
  directory: z
    .string()
    .optional()
    .describe(
      "Directory or file path to search in (defaults to current working directory)",
    ),
  flags: z
    .string()
    .optional()
    .describe(
      'Additional grep flags from the supported subset (e.g. "-rn", "-i", "-l", "-E", "-C 3", \'--include="*.js"\'). -r (recursive) is added by default when searching a directory. Alternate-pattern flags (-e, --regexp), file-reading flags (-f, --file, --exclude-from), bare "--", and stray tokens are rejected.',
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Searching for password hashes in config files')",
    ),
});

export function grep(ctx: ToolContext) {
  return tool({
    description: `Search file contents using grep.

Runs grep with the given pattern and optional flags. The directory parameter
also accepts this agent's tool-output: references, which search retained output
on the Apex host even when command execution uses a remote sandbox. When searching a
directory, -r (recursive) is included automatically unless you explicitly
provide flags that already contain it.

USEFUL FLAG COMBINATIONS:
  -rn           recursive + line numbers (default for dirs)
  -rni          recursive + line numbers + case-insensitive
  -rl           recursive, file names only
  -E            extended regex
  -P            Perl-compatible regex
  -C 3          show 3 lines of context around matches
  --include="*.js"  restrict to certain file types

Flags are limited to a safe subset: alternate-pattern flags (-e, --regexp),
file-reading flags (-f, --file, --exclude-from), a bare "--", and stray
tokens are rejected — any of these could turn the caller's pattern into a
file operand and search files outside the intended scope.
-R/--dereference-recursive is rejected while a file workspace scope is
active, because following symlinks can read files outside the scope.

Output is capped at ${MAX_OUTPUT_CHARS} characters at the producer — a search
that exceeds it reports truncated=true and an approximate window instead of a
match count. Narrow the search with flags or a more specific directory.
${ctx.sandbox?.type === "windows" ? "Windows supports -r, -n, -i, -l, -F, -E, and -P; regex patterns use .NET syntax. Use read_file line windows for surrounding context." : ""}`,
    inputSchema: grepInputSchema,
    toModelOutput: ({ output }) =>
      toolOutputForModel(ctx, output as GrepResult),
    execute: async ({ pattern, directory, flags }): Promise<GrepResult> => {
      const { fs } = resolveBackends(ctx);
      return fs.grep({ pattern, directory, flags });
    },
  });
}

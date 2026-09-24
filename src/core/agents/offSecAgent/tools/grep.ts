import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { tool } from "ai";
import { z } from "zod";
import { resolveFilePath } from "./fileWorkspace";
import type { UnifiedSandbox } from "./sandbox";
import {
  SANDBOX_OP_TIMEOUT_SECONDS,
  sandboxOpError,
  WIN_SCRIPT_COMMAND,
  WIN_SCRIPT_PRELUDE,
  winScriptEnv,
} from "./sandboxScript";
import type { ToolContext } from "./types";

// Producer bound: accumulation stops once this many characters are buffered —
// results are never collected unbounded and sliced afterwards.
const MAX_OUTPUT_CHARS = 50_000;
// One chunk of slack past the cap before the child is killed, so the cap
// boundary itself is captured exactly.
const KILL_SLACK_CHARS = 8_192;
const GREP_TIMEOUT_MS = 30_000;

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

export type GrepResult = {
  success: boolean;
  error: string;
  output: string;
  /** Exact only for a complete run; omitted for every incomplete outcome. */
  matchCount?: number;
  command: string;
  /** True when the producer bound stopped collection before grep finished. */
  truncated?: boolean;
};

export type GrepFlagValidation =
  | { ok: true; flags: string[] }
  | { ok: false; error: string };

// Default-deny flag allowlist. Anything that could inject an alternate
// pattern (-e/--regexp), a pattern FILE (-f/--file/--exclude-from), a
// terminator (--), or an extra operand (bare/stray tokens) would shift the
// caller's pattern or path out of position and bypass scoped roots — so
// only these forms pass.
const GREP_BOOLEAN_SHORTS = new Set([
  "E",
  "F",
  "G",
  "H",
  "I",
  "P",
  "R",
  "Z",
  "a",
  "c",
  "h",
  "i",
  "l",
  "n",
  "o",
  "q",
  "r",
  "s",
  "v",
  "w",
  "x",
]);
const GREP_NUMERIC_SHORTS = new Set(["A", "B", "C", "m"]);
const GREP_BOOLEAN_LONGS = new Set([
  "--basic-regexp",
  "--case-sensitive",
  "--count",
  "--dereference-recursive",
  "--extended-regexp",
  "--files-with-matches",
  "--files-without-match",
  "--fixed-strings",
  "--ignore-case",
  "--invert-match",
  "--line-number",
  "--line-regexp",
  "--no-filename",
  "--no-messages",
  "--null",
  "--only-matching",
  "--perl-regexp",
  "--quiet",
  "--recursive",
  "--silent",
  "--text",
  "--with-filename",
  "--word-regexp",
]);
const GREP_VALUE_LONGS = new Set([
  "--binary-files",
  "--exclude",
  "--exclude-dir",
  "--include",
]);

/**
 * Validates free-form flag text against the allowlist before it reaches any
 * grep invocation, local or remote. Numeric values are consumed only by the
 * flags that take them (-A/-B/-C/-m, inline or as the next token); a numeric
 * or bare token anywhere else is a stray operand and is rejected.
 */
export function validateGrepFlags(
  flags: string | undefined,
): GrepFlagValidation {
  const raw = flags ? flags.trim().split(/\s+/).filter(Boolean) : [];
  const out: string[] = [];
  let i = 0;
  while (i < raw.length) {
    const token = raw[i];
    if (token === "--") {
      return {
        ok: false,
        error:
          "bare -- is not allowed in flags — the pattern and path are passed as separate arguments",
      };
    }
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      const name = eq === -1 ? token : token.slice(0, eq);
      if (GREP_BOOLEAN_LONGS.has(name)) {
        out.push(token);
        i++;
        continue;
      }
      if (GREP_VALUE_LONGS.has(name)) {
        if (eq === -1 || eq === token.length - 1) {
          return {
            ok: false,
            error: `${name} requires a =VALUE form (e.g. ${name}=*.js)`,
          };
        }
        // Strip matched surrounding quotes so the documented
        // --include="*.js" form reaches grep as a plain glob.
        const value = token
          .slice(eq + 1)
          .replace(/^"(.*)"$/, "$1")
          .replace(/^'(.*)'$/, "$1");
        out.push(`${name}=${value}`);
        i++;
        continue;
      }
      return { ok: false, error: `unsupported grep flag: ${name}` };
    }
    if (token.startsWith("-") && token.length > 1) {
      const letters = token.slice(1);
      let valueFromNext = false;
      for (let j = 0; j < letters.length; j++) {
        const ch = letters[j];
        if (GREP_NUMERIC_SHORTS.has(ch)) {
          const rest = letters.slice(j + 1);
          if (rest.length > 0) {
            if (!/^\d+$/.test(rest)) {
              return {
                ok: false,
                error: `-${ch} expects a number, got "${rest}"`,
              };
            }
            break; // inline value (-C3) consumed the cluster
          }
          const next = raw[i + 1];
          if (next === undefined || !/^\d+$/.test(next)) {
            return {
              ok: false,
              error: `-${ch} requires a following numeric argument (e.g. "-${ch} 3")`,
            };
          }
          out.push(token, next);
          i += 2;
          valueFromNext = true;
          break;
        }
        if (!GREP_BOOLEAN_SHORTS.has(ch)) {
          const hint =
            ch === "e"
              ? " (the pattern is passed separately; an alternate pattern here would turn the caller's pattern into a file operand)"
              : ch === "f"
                ? " (reads patterns from a file)"
                : "";
          return { ok: false, error: `unsupported grep flag: -${ch}${hint}` };
        }
      }
      if (valueFromNext) continue;
      out.push(token);
      i++;
      continue;
    }
    return {
      ok: false,
      error: `unexpected non-flag token in flags: "${token}" — only allowlisted grep flags and their numeric arguments (e.g. "-C 3") are accepted`,
    };
  }
  return { ok: true, flags: out };
}

function hasDereferenceFlag(tokens: string[]): boolean {
  return tokens.some(
    (t) => /^-[a-zA-Z]*R/.test(t) || t === "--dereference-recursive",
  );
}

export function grep(ctx: ToolContext) {
  return tool({
    description: `Search file contents using grep.

Runs grep with the given pattern and optional flags. When searching a
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
    execute: async ({ pattern, directory, flags }): Promise<GrepResult> => {
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Grep aborted by user",
          output: "",
          command: "",
        };
      }

      const validated = validateGrepFlags(flags);
      if (!validated.ok) {
        return {
          success: false,
          error: validated.error,
          output: "",
          command: "",
        };
      }

      let dir: string;
      try {
        dir = await resolveFilePath(ctx, directory || ".");
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          output: "",
          command: "",
        };
      }
      // The resolve await can straddle an abort; without this check the
      // signal's abort event fires before any listener is registered and the
      // search would run to completion.
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Grep aborted by user",
          output: "",
          command: "",
          truncated: true,
        };
      }

      if (ctx.fileWorkspaceRoot && hasDereferenceFlag(validated.flags)) {
        return {
          success: false,
          error:
            "-R/--dereference-recursive follows symlinks during recursion and can read files outside the file workspace — use -r instead",
          output: "",
          command: "",
        };
      }

      if (ctx.sandbox) {
        return runSandboxGrep(ctx, ctx.sandbox, dir, pattern, validated.flags);
      }

      const userFlags = validated.flags;
      // Add -r by default when the user hasn't specified it and we're targeting a directory
      const hasRecursive = userFlags.some(
        (f) => /^-[a-zA-Z]*r[a-zA-Z]*$/.test(f) || f === "--recursive",
      );
      const defaultFlags = hasRecursive ? [] : ["-r"];

      const args = [...defaultFlags, ...userFlags, "--", pattern, dir];
      const command = `grep ${args.join(" ")}`;

      return new Promise((resolve) => {
        const child = spawn("grep", args, {
          cwd: ctx.agentCwd,
          stdio: ["ignore", "pipe", "pipe"],
        });

        let stdout = "";
        let stderr = "";
        let stdoutTruncated = false;
        let stderrTruncated = false;
        let killedForCap = false;
        let killedByTimeout = false;
        let killedByAbort = false;
        let resolved = false;

        // Wire up abort signal — clean up in safeResolve to cover all exit paths
        let abortCleanup: (() => void) | undefined;
        if (ctx.abortSignal) {
          const abortHandler = () => {
            killedByAbort = true;
            stopCancellation();
            child.kill("SIGTERM");
          };
          ctx.abortSignal.addEventListener("abort", abortHandler, {
            once: true,
          });
          abortCleanup = () =>
            ctx.abortSignal?.removeEventListener("abort", abortHandler);
        }

        const stopCancellation = () => {
          clearTimeout(timeout);
          abortCleanup?.();
        };

        const safeResolve = (result: GrepResult) => {
          if (resolved) return;
          resolved = true;
          stopCancellation();
          resolve(result);
        };

        const timeout = setTimeout(() => {
          killedByTimeout = true;
          stopCancellation();
          child.kill("SIGTERM");
        }, GREP_TIMEOUT_MS);

        // Exit precedes stdio close; late cancellation must not relabel completed work.
        child.once("exit", stopCancellation);

        // Accumulation is bounded at the producer: once past the cap the
        // stream is destroyed (grep SIGPIPEs) instead of buffering forever.
        child.stdout.on("data", (data) => {
          if (stdoutTruncated) return;
          const chunk = data.toString();
          if (stdout.length + chunk.length > MAX_OUTPUT_CHARS) {
            stdout += chunk.slice(0, MAX_OUTPUT_CHARS - stdout.length);
            stdoutTruncated = true;
            killedForCap = true;
            stopCancellation();
            child.stdout.destroy();
            child.kill("SIGTERM");
            return;
          }
          stdout += chunk;
        });

        child.stderr.on("data", (data) => {
          if (stderrTruncated) return;
          const chunk = data.toString();
          if (stderr.length + chunk.length > KILL_SLACK_CHARS) {
            stderr += chunk.slice(0, KILL_SLACK_CHARS - stderr.length);
            stderrTruncated = true;
            return;
          }
          stderr += chunk;
        });

        child.on("close", (code) => {
          const interrupted = killedForCap || killedByTimeout || killedByAbort;
          // grep exits 1 with no stderr only when it genuinely found nothing.
          const noMatch = !interrupted && code === 1 && stderr === "";

          const output = killedForCap
            ? `${stdout}\n\n(truncated at ${MAX_OUTPUT_CHARS} characters — narrow your search; match count omitted because the full result was not captured)`
            : interrupted
              ? stdout
              : noMatch || (code === 0 && stdout === "")
                ? "(no matches)"
                : stdout;

          const error = killedByAbort
            ? "Grep aborted by user"
            : killedByTimeout
              ? `Grep timed out after ${GREP_TIMEOUT_MS / 1000}s — partial output only`
              : killedForCap
                ? `output capped at ${MAX_OUTPUT_CHARS} characters before grep finished`
                : noMatch || code === 0
                  ? ""
                  : stderr || `Exit code: ${code}`;

          safeResolve({
            // An interrupted or failed search is never a clean success, and
            // its (possibly empty) output is partial evidence, not a verdict.
            success: !interrupted && (code === 0 || noMatch),
            error,
            output,
            // An exact count needs a complete run — omitted for every
            // incomplete or nonzero-error outcome.
            ...(interrupted || (code !== 0 && !noMatch)
              ? {}
              : {
                  matchCount: stdout ? stdout.trimEnd().split("\n").length : 0,
                }),
            command,
            ...(interrupted ? { truncated: true } : {}),
          });
        });

        child.on("error", (err) => {
          safeResolve({
            success: false,
            error: err.message,
            output: "",
            command,
          });
        });
      });
    },
  });
}

// --- Sandbox grep ----------------------------------------------------------
//
// A sandboxed agent's files live inside the sandbox, so searches run there —
// never against the host filesystem. Both backends emit matches plus a nonce
// exit marker (the http-request pattern): a missing marker means the producer
// bound (head -c / emission cap) stopped collection before grep finished.

type SandboxGrepOutcome =
  | { kind: "complete"; exitCode: number; output: string; stderr: string }
  | { kind: "truncated"; output: string; stderr: string }
  | { kind: "failed"; error: string; output: string; stderr: string };

function parseSandboxGrep(
  stdout: string,
  marker: string,
): { exitCode: number; output: string } | undefined {
  const match = stdout.match(new RegExp(`\\n?${marker}(\\d+)\\n?$`));
  if (!match || match.index === undefined) return undefined;
  return {
    exitCode: Number.parseInt(match[1], 10),
    output: stdout.slice(0, match.index),
  };
}

async function runSandboxGrepLinux(
  sandbox: UnifiedSandbox,
  dir: string,
  pattern: string,
  userFlags: string[],
): Promise<SandboxGrepOutcome> {
  const nonce = randomBytes(8).toString("hex");
  const marker = `__APEX_GREP_EXIT_${nonce}_`;
  const hasRecursive = userFlags.some(
    (f) => /^-[a-zA-Z]*r[a-zA-Z]*$/.test(f) || f === "--recursive",
  );
  const args = [...(hasRecursive ? [] : ["-r"]), ...userFlags];
  // Flags arrive via env and are word-split into an array without any shell
  // interpretation; pattern and path never touch the command string.
  const command = [
    // noglob: a validated --include=*.js value must reach grep literally —
    // here-string expansion could otherwise glob it against the cwd.
    'set -f; read -r -a APEX_GF <<< "$APEX_GREP_FLAGS"',
    `( grep "\${APEX_GF[@]}" -- "$APEX_GREP_PATTERN" "$APEX_GREP_PATH"; printf '\\n${marker}%s\\n' "$?" ) | head -c ${MAX_OUTPUT_CHARS + KILL_SLACK_CHARS}`,
  ].join("\n");
  const result = await sandbox.execute(command, {
    timeout: GREP_TIMEOUT_MS / 1000,
    retries: 0,
    envVars: {
      APEX_GREP_PATTERN: pattern,
      APEX_GREP_PATH: dir,
      APEX_GREP_FLAGS: args.join(" "),
    },
  });
  const parsed = parseSandboxGrep(result.stdout || "", marker);
  if (parsed) {
    return {
      kind: "complete",
      exitCode: parsed.exitCode,
      output: parsed.output,
      stderr: result.stderr || "",
    };
  }
  // head -c makes the pipeline exit 0 even after cutting grep short; a
  // nonzero adapter exit with no marker means the run was killed outright.
  if (result.success && result.exitCode === 0) {
    return {
      kind: "truncated",
      output: (result.stdout || "").slice(0, MAX_OUTPUT_CHARS),
      stderr: result.stderr || "",
    };
  }
  return {
    kind: "failed",
    error: sandboxOpError("grep", result),
    output: (result.stdout || "").slice(0, MAX_OUTPUT_CHARS),
    stderr: result.stderr || "",
  };
}

// Windows: Select-String over a manual stack walk. Reparse points are
// skipped entirely — searching a symlinked file would read outside the
// scope, and grep -r never dereferences. Supported flag subset: -i, -n, -l,
// -F; -E/-P map to .NET regex. The host rejects every other flag first.
// Match state lives in $script: scope: PowerShell assignment inside a
// function creates a local, so counters set inside Search-File would never
// reach the walker. Select-String streams through the pipeline — foreach
// would materialize every match before the cap could stop it.
const WIN_GREP_SCRIPT = [
  WIN_SCRIPT_PRELUDE,
  "try{",
  "$p=[Environment]::GetEnvironmentVariable('APEX_GREP_PATH')",
  "$pattern=[Environment]::GetEnvironmentVariable('APEX_GREP_PATTERN')",
  "$opts=[Environment]::GetEnvironmentVariable('APEX_GREP_OPTS')",
  "$mark=[Environment]::GetEnvironmentVariable('APEX_GREP_MARKER')",
  "$cap=[int64][Environment]::GetEnvironmentVariable('APEX_GREP_CAP')",
  "$caseSensitive=($opts -notmatch '(^|,)i(,|$)')",
  "$lineNums=($opts -match '(^|,)n(,|$)')",
  "$listOnly=($opts -match '(^|,)l(,|$)')",
  "$simple=($opts -match '(^|,)F(,|$)')",
  "$script:found=$false",
  "$script:hadError=$false",
  "$script:emitted=[int64]0",
  "$script:capped=$false",
  "function Search-File([string]$f){",
  "$sp=@{LiteralPath=$f;Pattern=$pattern}",
  "if($caseSensitive){$sp.CaseSensitive=$true}",
  "if($simple){$sp.SimpleMatch=$true}",
  "if($listOnly){$sp.List=$true}",
  "try{ Select-String @sp | ForEach-Object {",
  "if($script:capped){return}",
  "$script:found=$true",
  "if($listOnly){$line=$f}",
  'elseif($lineNums){$line="$($f):$($_.LineNumber):$($_.Line)"}',
  'else{$line="$($f):$($_.Line)"}',
  "$len=$line.Length+1",
  "if($script:emitted+$len -gt $cap){$script:capped=$true;throw 'Search capture limit reached'}",
  "[Console]::Out.WriteLine($line)",
  "$script:emitted+=$len",
  "} }catch{if(-not $script:capped){throw}}",
  "}",
  "$stack=New-Object 'System.Collections.Generic.Stack[string]'",
  "$item=Get-Item -LiteralPath $p -Force",
  "if(($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0){$stack.Push($p)}else{Search-File $p}",
  "while($stack.Count -gt 0 -and -not $script:capped){",
  "$d=$stack.Pop()",
  "$di=New-Object IO.DirectoryInfo($d)",
  "foreach($e in $di.EnumerateFileSystemInfos()){",
  "$attr=$e.Attributes",
  "if(($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}",
  "if(($attr -band [IO.FileAttributes]::Directory) -ne 0){$stack.Push($e.FullName);continue}",
  "try{Search-File $e.FullName}catch{",
  "$script:hadError=$true",
  '[Console]::Error.WriteLine("grep: $($e.FullName): $($_.Exception.Message)")',
  "}",
  "if($script:capped){break}",
  "}",
  "}",
  "if($script:capped){exit 3}",
  "$code=1",
  "if($script:hadError){$code=2}elseif($script:found){$code=0}",
  '[Console]::Out.Write("`n$mark$code`n")',
  "exit 0",
  "}catch{",
  "[Console]::Error.WriteLine($_.Exception.Message)",
  "exit 2",
  "}",
].join("\n");

const WIN_GREP_SUPPORTED_FLAGS = new Set(["i", "n", "l", "F", "E", "P", "r"]);

async function runSandboxGrepWindows(
  sandbox: UnifiedSandbox,
  dir: string,
  pattern: string,
  userFlags: string[],
): Promise<SandboxGrepOutcome> {
  // Clusters like -rni are fine; every letter must be in the supported set.
  for (const token of userFlags) {
    const letters = token.replace(/^-+/, "").split("");
    const unsupported = letters.filter((l) => !WIN_GREP_SUPPORTED_FLAGS.has(l));
    if (unsupported.length > 0) {
      return {
        kind: "failed",
        error: `windows sandbox search supports only -i, -n, -l, -F, -E, -P, -r — "${token}" is not available there`,
        output: "",
        stderr: "",
      };
    }
  }
  const nonce = randomBytes(8).toString("hex");
  const marker = `__APEX_GREP_EXIT_${nonce}_`;
  const opts = userFlags.flatMap((flag) => flag.slice(1).split("")).join(",");
  const result = await sandbox.execute(WIN_SCRIPT_COMMAND, {
    timeout: SANDBOX_OP_TIMEOUT_SECONDS,
    retries: 0,
    envVars: {
      ...winScriptEnv(WIN_GREP_SCRIPT),
      APEX_GREP_PATH: dir,
      APEX_GREP_PATTERN: pattern,
      APEX_GREP_OPTS: opts,
      APEX_GREP_MARKER: marker,
      APEX_GREP_CAP: String(MAX_OUTPUT_CHARS + KILL_SLACK_CHARS),
    },
  });
  const parsed = parseSandboxGrep(result.stdout || "", marker);
  if (parsed) {
    return {
      kind: "complete",
      exitCode: parsed.exitCode,
      output: parsed.output,
      stderr: result.stderr || "",
    };
  }
  if (result.exitCode === 3) {
    return {
      kind: "truncated",
      output: (result.stdout || "").slice(0, MAX_OUTPUT_CHARS),
      stderr: result.stderr || "",
    };
  }
  return {
    kind: "failed",
    error: sandboxOpError("grep", result),
    output: (result.stdout || "").slice(0, MAX_OUTPUT_CHARS),
    stderr: result.stderr || "",
  };
}

async function runSandboxGrep(
  ctx: ToolContext,
  sandbox: UnifiedSandbox,
  dir: string,
  pattern: string,
  userFlags: string[],
): Promise<GrepResult> {
  const command = `grep ${["-r", ...userFlags].join(" ")} -- ${pattern} ${dir}`;
  const outcome =
    sandbox.type === "windows"
      ? await runSandboxGrepWindows(sandbox, dir, pattern, userFlags)
      : await runSandboxGrepLinux(sandbox, dir, pattern, userFlags);
  // The sandbox adapter cannot cancel an in-flight command; an abort that
  // landed during the remote run is relabeled here (with whatever evidence
  // arrived) rather than reported as a completed search — mirroring the local
  // rule that an abort during flight stays interrupted even on exit 0.
  if (ctx.abortSignal?.aborted) {
    const partial =
      outcome.kind === "failed"
        ? ""
        : outcome.output.slice(0, MAX_OUTPUT_CHARS);
    return {
      success: false,
      error: "Grep aborted by user",
      output: partial,
      command,
      truncated: true,
    };
  }
  if (outcome.kind === "failed") {
    return {
      success: false,
      error: outcome.error,
      output: outcome.output,
      command,
    };
  }
  if (outcome.kind === "truncated") {
    return {
      success: false,
      error: `output capped at ${MAX_OUTPUT_CHARS} characters before the search finished`,
      output:
        outcome.output.length > 0
          ? `${outcome.output}\n\n(truncated at ${MAX_OUTPUT_CHARS} characters — narrow your search; match count omitted because the full result was not captured)`
          : outcome.output,
      command,
      truncated: true,
    };
  }
  const noMatch = outcome.exitCode === 1 && outcome.stderr === "";
  const output =
    outcome.exitCode === 1 && noMatch && outcome.output === ""
      ? "(no matches)"
      : outcome.output.slice(0, MAX_OUTPUT_CHARS);
  return {
    success: outcome.exitCode === 0 || noMatch,
    error:
      outcome.exitCode === 0 || noMatch
        ? ""
        : outcome.stderr || `Exit code: ${outcome.exitCode}`,
    output,
    ...(outcome.exitCode === 0 || noMatch
      ? {
          matchCount: outcome.output
            ? outcome.output.trimEnd().split("\n").length
            : 0,
        }
      : {}),
    command,
  };
}

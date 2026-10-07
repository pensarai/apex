import { createHash } from "node:crypto";
import { collectCommand } from "../../../tools/backends/collectCommand";
import {
  resolveBackends,
  resolveProgramRunner,
} from "../../../tools/backends/resolve";
import type { ToolContext } from "./types";

export type ScriptLanguage = "bash" | "python" | "javascript";

export type ScriptSyntaxStatus = "valid" | "invalid" | "unchecked";

export interface ScriptSyntaxResult {
  status: ScriptSyntaxStatus;
  /**
   * sha256 of the script bytes the check examined, certifying that the
   * verdict applied to the exact bytes present after the check. Present
   * whenever the bytes could be read; absent when even that failed.
   */
  contentHash?: string;
  /** Single-line `path:line: message` diagnostic; only for `invalid`. */
  detail?: string;
  /** Why the check could not decide; only for `unchecked`. */
  reason?: string;
}

// Measured worst case (python startup on a max-size 1 MiB script) is ~0.6s;
// 5s keeps ~9x headroom for loaded sandboxes while still bounding the path.
export const SCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS = 5;

const CHECKER_OUTPUT_LIMIT = 240;

// The runner itself is the checker, via its parse-only flag, so the runtime,
// dialect and module mode that check are the ones that will execute. The
// Python variant uses compile(..., "exec") — full module compilation without
// executing the produced bytecode, so top-level `return` is rejected exactly
// as a real run would reject it — and tokenize.open so BOM and PEP 263 coding
// declarations decode as real compilation would, without py_compile's
// __pycache__ artifact next to the staged script.
const CHECKER_ARGS: Record<ScriptLanguage, (scriptPath: string) => string[]> = {
  bash: (scriptPath) => ["-n", scriptPath],
  javascript: (scriptPath) => ["--check", scriptPath],
  python: (scriptPath) => [
    "-c",
    'import sys, tokenize; compile(tokenize.open(sys.argv[1]).read(), sys.argv[1], "exec")',
    scriptPath,
  ],
};

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function bound(text: string): string {
  const singleLine = text.split(/\r?\n/).find((line) => line.trim() !== "");
  return (singleLine ?? "").slice(0, CHECKER_OUTPUT_LIMIT);
}

function digest(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * Extracts a concise `line: message` pair from checker stderr, anchored to
 * the staged path so interpreter frames that are not the target script
 * (e.g. Python's `-c` frame) can never be reported as its diagnostic.
 */
function extractLineDiagnostic(
  language: ScriptLanguage,
  scriptPath: string,
  stderr: string,
): { line: string; message: string } | undefined {
  const path = escapeRegExp(scriptPath);
  if (language === "bash") {
    const match = stderr.match(new RegExp(`^${path}: line (\\d+): (.+)$`, "m"));
    if (match) return { line: match[1], message: match[2] };
    return undefined;
  }
  if (language === "python") {
    const frame = stderr.match(
      new RegExp(`^\\s*File "${path}", line (\\d+)`, "m"),
    );
    const error = stderr.match(/^(.*Error:.+)$/m);
    if (frame && error) return { line: frame[1], message: error[1].trim() };
    return undefined;
  }
  const caret = stderr.match(new RegExp(`^${path}:(\\d+)(?::\\d+)?\\s*$`, "m"));
  const error = stderr.match(/^(\w*Error): (.+)$/m);
  if (caret && error)
    return { line: caret[1], message: `${error[1]}: ${error[2]}` };
  return undefined;
}

function verdictFromCheckerOutcome(
  language: ScriptLanguage,
  scriptPath: string,
  timeoutSeconds: number,
  result: {
    stdout: string;
    stderr: string;
    exitCode: number;
    timedOut: boolean;
  },
): ScriptSyntaxResult {
  if (result.exitCode === 0 && !result.timedOut) {
    return { status: "valid" };
  }
  if (result.timedOut || result.exitCode === 124) {
    return {
      status: "unchecked",
      reason: `syntax checker timed out after ${timeoutSeconds}s`,
    };
  }
  // 130 is this stack's abort exit code, not a checker verdict.
  if (result.exitCode === 130) {
    return { status: "unchecked", reason: "syntax check was aborted" };
  }
  if (result.exitCode === 126 || result.exitCode === 127) {
    return {
      status: "unchecked",
      reason: `syntax checker unavailable (exit ${result.exitCode})`,
    };
  }
  // The native argv transport surfaces a missing runner as exit 1 with a
  // spawn-ENOENT stderr instead of the shell's 127; remote shells say
  // "command not found". Both mean no checker, not a script verdict.
  if (/\bspawn\s+\S+\s+ENOENT\b|command not found/i.test(result.stderr)) {
    return {
      status: "unchecked",
      reason: `syntax checker unavailable: ${bound(result.stderr)}`,
    };
  }
  const diagnostic = extractLineDiagnostic(language, scriptPath, result.stderr);
  if (diagnostic) {
    return {
      status: "invalid",
      detail: `${scriptPath}:${diagnostic.line}: ${bound(diagnostic.message)}`,
    };
  }
  return {
    status: "unchecked",
    reason: `syntax checker exited ${result.exitCode} without a file/line diagnostic: ${bound(
      result.stderr || result.stdout,
    )}`,
  };
}

/**
 * Parse-only native syntax check for a script file, through the same
 * transport, runner, env and cwd that will execute it. The checker never
 * imports or runs the target program, never mutates the payload, and never
 * rolls back any write; a `valid` verdict says the bytes compile in the
 * selected dialect and nothing about the finding's effect. Read or transport
 * failures, missing checkers and timeouts all yield `unchecked`, which must
 * not block execution. Every step is bounded: two capped single-file reads
 * bracket one short-deadline checker command, and only a verdict whose
 * pre/post reads hash identically is certified against the bytes that will
 * execute.
 */
export async function checkScriptSyntax(
  ctx: ToolContext,
  params: {
    language: ScriptLanguage;
    /** The exact runner that will execute the script (e.g. `python3`). */
    runner: string;
    /** Absolute path of the script whose bytes will run. */
    scriptPath: string;
    timeoutSeconds?: number;
    abortSignal?: AbortSignal;
  },
): Promise<ScriptSyntaxResult> {
  const timeoutSeconds =
    params.timeoutSeconds ?? SCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS;
  const fs = resolveBackends(ctx).fs;
  let contentHash: string | undefined;

  try {
    const staged = await fs.readRaw(params.scriptPath);
    if (!staged.success) {
      return {
        status: "unchecked",
        reason: `could not read the script bytes: ${bound(staged.error)}`,
      };
    }
    contentHash = digest(staged.content);

    const result = await collectCommand(
      resolveProgramRunner(ctx)(
        params.runner,
        CHECKER_ARGS[params.language](params.scriptPath),
        { timeoutSeconds, abortSignal: params.abortSignal },
      ),
    );
    const verdict = verdictFromCheckerOutcome(
      params.language,
      params.scriptPath,
      timeoutSeconds,
      result,
    );
    if (verdict.status === "unchecked") return { ...verdict, contentHash };

    // Certify the verdict against the bytes that will execute: a mismatch (or
    // a failed re-read) means the check ran against bytes that no longer
    // exist, so the verdict is stale and must be discarded, not certified.
    const verified = await fs.readRaw(params.scriptPath);
    if (!verified.success) {
      return {
        status: "unchecked",
        contentHash,
        reason: `could not re-read the script bytes after the check: ${bound(
          verified.error,
        )}`,
      };
    }
    if (digest(verified.content) !== contentHash) {
      return {
        status: "unchecked",
        contentHash,
        reason: "script bytes changed during the syntax check",
      };
    }
    return { ...verdict, contentHash };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      status: "unchecked",
      contentHash,
      reason: `syntax check failed: ${bound(message)}`,
    };
  }
}

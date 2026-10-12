import { createHash } from "node:crypto";
import { collectCommand } from "../../../tools/backends/collectCommand";
import {
  resolveBackends,
  resolveProgramRunner,
} from "../../../tools/backends/resolve";
import type { FsBackend } from "../../../tools/backends/types";
import type { ToolContext } from "./types";

export type ScriptLanguage = "bash" | "python" | "javascript";

export type ScriptSyntaxStatus = "valid" | "invalid" | "unchecked";

export interface ScriptSyntaxResult {
  status: ScriptSyntaxStatus;
  /**
   * sha256 over the UTF-8 text read back around the check (readRaw returns
   * text, not raw bytes); equal pre/post hashes mean the checked text is
   * unchanged. Absent when even the read failed.
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

// Byte cap for the text reads this check owns; matches the workspace
// text-tool cap, and a larger script surfaces as `unchecked`.
export const SCRIPT_SYNTAX_CHECK_MAX_BYTES = 1024 * 1024;

const CHECKER_OUTPUT_LIMIT = 240;

// The runner itself is the checker via its parse-only flag, so runtime,
// dialect and module mode match execution. The Python snippet imports
// nothing filesystem-resolvable (sys is builtin) — a workspace module like
// tokenize.py must not shadow stdlib and execute during the check — and
// -S skips site/sitecustomize so a configured PYTHONPATH startup hook
// cannot run either; compile on raw bytes rejects top-level `return`
// (ast.parse would not) without executing bytecode or writing a
// __pycache__ artifact, and handles BOM/PEP 263 decoding itself.
const CHECKER_ARGS: Record<ScriptLanguage, (scriptPath: string) => string[]> = {
  bash: (scriptPath) => ["-n", scriptPath],
  javascript: (scriptPath) => ["--check", scriptPath],
  python: (scriptPath) => [
    "-S",
    "-c",
    'import sys; compile(open(sys.argv[1], "rb").read(), sys.argv[1], "exec")',
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
 * Extracts a `line: message` pair from checker stderr, anchored to the
 * script path so frames that are not the target (e.g. Python's `-c` frame)
 * can never be misreported as its diagnostic.
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
  const diagnostic = extractLineDiagnostic(language, scriptPath, result.stderr);
  if (diagnostic) {
    return {
      status: "invalid",
      detail: `${scriptPath}:${diagnostic.line}: ${bound(diagnostic.message)}`,
    };
  }
  // Check launch-failure text only after diagnostics, which can echo arbitrary source.
  if (/\bspawn\s+\S+\s+ENOENT\b|command not found/i.test(result.stderr)) {
    return {
      status: "unchecked",
      reason: `syntax checker unavailable: ${bound(result.stderr)}`,
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
 * Parse-only native syntax check through the same transport, runner, env and
 * cwd that will execute the script. Never imports or runs the target,
 * mutates the payload, or rolls back writes. `valid` only says the text
 * parsed in the selected dialect at check time — not that the finding's
 * effect is proven, and not anything about bytes that change afterwards.
 * Read/transport failures, missing checkers and timeouts yield `unchecked`,
 * which must not block execution. Reads the check owns are byte-capped
 * (injected backends apply their own caps); the checker command carries the
 * wall-clock deadline.
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
    /**
     * Owning fs seam. Defaults to the workspace backend (declared artifacts
     * stay confined to it); pass the artifact owner for a retained local PoC
     * that may live outside a confined helper workspace.
     */
    fs?: FsBackend;
  },
): Promise<ScriptSyntaxResult> {
  const timeoutSeconds =
    params.timeoutSeconds ?? SCRIPT_SYNTAX_CHECK_TIMEOUT_SECONDS;
  const fs = params.fs ?? resolveBackends(ctx).fs;
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

    // A post-check mismatch (or failed re-read) means the verdict describes
    // text that no longer exists — discard it rather than certify.
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

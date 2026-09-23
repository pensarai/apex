import { type ChildProcess, spawn } from "node:child_process";
import type { CommandBackend } from "../tools/backends/types";

const KILL_ESCALATE_MS = 2_000;

function killChildTree(
  child: ChildProcess,
  signal: NodeJS.Signals,
  detached: boolean,
): void {
  const pid = child.pid;
  if (detached && pid && process.platform !== "win32") {
    try {
      process.kill(-pid, signal);
    } catch {
      /* process may be gone */
    }
  }
  try {
    child.kill(signal);
  } catch {
    /* already exited */
  }
}

/**
 * Run argv[0] with argv.slice(1), bounded stdout/stderr size and wall-clock timeout.
 * On timeout: SIGTERM, then SIGKILL after {@link KILL_ESCALATE_MS}.
 */
export async function runSpawnBounded(input: {
  command: readonly string[];
  cwd: string;
  timeoutSeconds: number;
  maxTotalBytes: number;
  /** When true (non-Windows), spawn in a new process group so `kill(-pid)` hits children. */
  detached?: boolean;
}): Promise<{
  stdout: string;
  stderr: string;
  exitCode: number | null;
  outputTruncated: boolean;
  timedOut: boolean;
}> {
  const program = input.command[0];
  if (!program) {
    return {
      stdout: "",
      stderr: "Empty command",
      exitCode: null,
      outputTruncated: false,
      timedOut: false,
    };
  }

  const detached = input.detached === true && process.platform !== "win32";

  return new Promise((resolve) => {
    const child = spawn(program, input.command.slice(1), {
      cwd: input.cwd,
      stdio: ["ignore", "pipe", "pipe"],
      detached,
    });

    let stdout = "";
    let stderr = "";
    let totalBytes = 0;
    let outputTruncated = false;
    let settled = false;
    let killedByTimeout = false;
    let escalateTimer: ReturnType<typeof setTimeout> | undefined;
    let timeoutTimer: ReturnType<typeof setTimeout> | undefined;

    const finish = (result: {
      stdout: string;
      stderr: string;
      exitCode: number | null;
      outputTruncated: boolean;
      timedOut: boolean;
    }) => {
      if (settled) return;
      settled = true;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (escalateTimer) clearTimeout(escalateTimer);
      resolve(result);
    };

    const append = (target: "stdout" | "stderr", data: Buffer) => {
      if (totalBytes >= input.maxTotalBytes) {
        outputTruncated = true;
        return;
      }
      const room = input.maxTotalBytes - totalBytes;
      const buf = data.byteLength > room ? data.subarray(0, room) : data;
      const text = buf.toString();
      if (target === "stdout") stdout += text;
      else stderr += text;
      totalBytes += buf.byteLength;
      if (buf.byteLength < data.byteLength) outputTruncated = true;
    };

    timeoutTimer = setTimeout(() => {
      killedByTimeout = true;
      killChildTree(child, "SIGTERM", detached);
      escalateTimer = setTimeout(() => {
        if (settled) return;
        killChildTree(child, "SIGKILL", detached);
        finish({
          stdout,
          stderr: `${stderr}\n[apex] command timed out (SIGKILL)\n`,
          exitCode: 124,
          outputTruncated,
          timedOut: true,
        });
      }, KILL_ESCALATE_MS);
    }, input.timeoutSeconds * 1000);

    child.stdout?.on("data", (data: Buffer) => append("stdout", data));
    child.stderr?.on("data", (data: Buffer) => append("stderr", data));

    child.on("close", (code) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (escalateTimer) clearTimeout(escalateTimer);
      const timedOut = killedByTimeout;
      finish({
        stdout,
        stderr,
        exitCode: code,
        outputTruncated,
        timedOut,
      });
    });

    child.on("error", (error) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (escalateTimer) clearTimeout(escalateTimer);
      finish({
        stdout,
        stderr: stderr + error.message,
        exitCode: null,
        outputTruncated,
        timedOut: killedByTimeout,
      });
    });
  });
}

function shellQuoteArg(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** `argv` joined into a single shell-quoted string, `cd`'d into `cwd` first — `CommandBackend.run` takes one command string, not argv + cwd. */
export function buildShellCommand(
  argv: readonly string[],
  cwd: string,
): string {
  const quotedArgv = argv.map(shellQuoteArg).join(" ");
  return `cd ${shellQuoteArg(cwd)} && ${quotedArgv}`;
}

/**
 * {@link runSpawnBounded} on the host, or through a host-injected
 * {@link CommandBackend} so the analyzer runs wherever that backend routes
 * commands (the sandbox that holds the clone, on the durable path).
 */
export async function runCommandBounded(
  command: CommandBackend | undefined,
  argv: readonly string[],
  input: {
    cwd: string;
    timeoutSeconds: number;
    maxTotalBytes: number;
    abortSignal?: AbortSignal;
  },
): Promise<{
  stdout: string;
  stderr: string;
  exitCode: number | null;
  outputTruncated: boolean;
  timedOut: boolean;
}> {
  if (!command) {
    return runSpawnBounded({
      command: argv,
      cwd: input.cwd,
      timeoutSeconds: input.timeoutSeconds,
      maxTotalBytes: input.maxTotalBytes,
      detached: false,
    });
  }
  if (!argv[0]) {
    return {
      stdout: "",
      stderr: "Empty command",
      exitCode: 1,
      outputTruncated: false,
      timedOut: false,
    };
  }

  let stdout = "";
  let stderr = "";
  let totalBytes = 0;
  let outputTruncated = false;
  let exitCode = 0;
  let timedOut = false;

  const append = (target: "stdout" | "stderr", text: string): void => {
    if (totalBytes >= input.maxTotalBytes) {
      outputTruncated = true;
      return;
    }
    const room = input.maxTotalBytes - totalBytes;
    let bounded = text;
    if (Buffer.byteLength(text) > room) {
      bounded = Buffer.from(text).subarray(0, room).toString();
      outputTruncated = true;
    }
    if (target === "stdout") stdout += bounded;
    else stderr += bounded;
    totalBytes += Buffer.byteLength(bounded);
  };

  for await (const event of command.run(buildShellCommand(argv, input.cwd), {
    timeoutSeconds: input.timeoutSeconds,
    abortSignal: input.abortSignal,
  })) {
    if (event.type === "stdout") append("stdout", event.bytes);
    else if (event.type === "stderr") append("stderr", event.bytes);
    else if (event.type === "end") {
      exitCode = event.exitCode;
      timedOut = event.timedOut;
    }
  }

  return { stdout, stderr, exitCode, outputTruncated, timedOut };
}

import { type ChildProcess, spawn } from "node:child_process";

const KILL_ESCALATE_MS = 2_000;

function killChildTree(child: ChildProcess, signal: NodeJS.Signals): void {
  const pid = child.pid;
  if (pid && process.platform !== "win32") {
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

  const detached =
    input.detached === true && process.platform !== "win32";

  return new Promise((resolve) => {
    const child = spawn(program, input.command.slice(1), {
      cwd: input.cwd,
      stdio: ["ignore", "pipe", "pipe"],
      detached,
    });

    let stdout = "";
    let stderr = "";
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

    const append = (target: "stdout" | "stderr", chunk: string) => {
      const combined = stdout.length + stderr.length;
      if (combined >= input.maxTotalBytes) {
        outputTruncated = true;
        return;
      }
      const room = input.maxTotalBytes - combined;
      const slice = chunk.length > room ? chunk.slice(0, room) : chunk;
      if (target === "stdout") stdout += slice;
      else stderr += slice;
      if (slice.length < chunk.length) outputTruncated = true;
    };

    timeoutTimer = setTimeout(() => {
      killedByTimeout = true;
      killChildTree(child, "SIGTERM");
      escalateTimer = setTimeout(() => {
        if (settled) return;
        killChildTree(child, "SIGKILL");
        finish({
          stdout,
          stderr: `${stderr}\n[apex] command timed out (SIGKILL)\n`,
          exitCode: 124,
          outputTruncated,
          timedOut: true,
        });
      }, KILL_ESCALATE_MS);
    }, input.timeoutSeconds * 1000);

    child.stdout?.on("data", (data: Buffer) => append("stdout", data.toString()));
    child.stderr?.on("data", (data: Buffer) => append("stderr", data.toString()));

    child.on("close", (code) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (escalateTimer) clearTimeout(escalateTimer);
      const timedOut = killedByTimeout || code === 124;
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

import { randomUUID } from "node:crypto";
import type { Sandbox } from "@daytona/sdk";
import type {
  SandboxExecuteOptions,
  UnifiedSandbox,
} from "../agents/offSecAgent/tools";

type ExecutionProcess = Pick<
  Sandbox["process"],
  "createSession" | "executeSessionCommand" | "deleteSession"
>;

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function commandText(command: string, options: SandboxExecuteOptions): string {
  if (command.includes("\0") || options.cwd?.includes("\0")) {
    throw new Error("Sandbox commands and paths cannot contain NUL bytes");
  }
  const environment = Object.entries(options.envVars ?? {}).map(
    ([key, value]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || value.includes("\0")) {
        throw new Error("Invalid sandbox command environment");
      }
      return shellQuote(`${key}=${value}`);
    },
  );
  const invocation = [
    "env",
    ...environment,
    "/bin/bash",
    "--noprofile",
    "--norc",
    "-c",
    shellQuote(command),
  ].join(" ");
  return options.cwd
    ? `cd -- ${shellQuote(options.cwd)} && ${invocation}`
    : invocation;
}

/** Attaches tools to an already-owned sandbox; provisioning authority stays with the caller. */
export function createDaytonaExecutionSandbox(
  process: ExecutionProcess,
  signal?: AbortSignal,
): UnifiedSandbox & AsyncDisposable {
  const lifetime = new AbortController();
  const sessions = new Set<string>();
  const pending = new Set<Promise<unknown>>();
  let disposed = false;
  async function release(id: string) {
    await process.deleteSession(id).catch((error: unknown) => {
      if ((error as { statusCode?: number }).statusCode !== 404) throw error;
    });
    sessions.delete(id);
  }
  async function run(command: string, options: SandboxExecuteOptions = {}) {
    if (disposed) throw new Error("Execution sandbox transport is disposed");
    const timeoutSeconds = options.timeout ?? 120;
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
      throw new Error("Sandbox command timeout must be positive seconds");
    }
    const text = commandText(command, options);
    const signals = [lifetime.signal, signal, options.abortSignal].filter(
      (value): value is AbortSignal => value !== undefined,
    );
    const abort = signals.length ? AbortSignal.any(signals) : undefined;
    abort?.throwIfAborted();
    const sessionId = `apex-command-${randomUUID()}`;
    sessions.add(sessionId);
    let completed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let rejectAbort: (() => void) | undefined;
    try {
      await process.createSession(sessionId);
      abort?.throwIfAborted();
      const interrupted = new Promise<never>((_, reject) => {
        rejectAbort = () =>
          reject(abort?.reason ?? new DOMException("Aborted", "AbortError"));
        abort?.addEventListener("abort", rejectAbort, { once: true });
        if (abort?.aborted) rejectAbort();
        timer = setTimeout(
          () =>
            reject(
              new Error(`Sandbox command exceeded ${timeoutSeconds} seconds`),
            ),
          (timeoutSeconds + 5) * 1_000,
        );
      });
      const result = await Promise.race([
        process.executeSessionCommand(
          sessionId,
          { command: text, runAsync: false },
          timeoutSeconds,
        ),
        interrupted,
      ]);
      if (
        typeof result.exitCode !== "number" ||
        !Number.isInteger(result.exitCode)
      ) {
        throw new Error("Sandbox command did not report a terminal exit code");
      }
      completed = true;
      return {
        stdout: result.stdout ?? result.output ?? "",
        stderr: result.stderr ?? "",
        exitCode: result.exitCode,
        success: result.exitCode === 0,
      };
    } finally {
      if (timer) clearTimeout(timer);
      if (rejectAbort) abort?.removeEventListener("abort", rejectAbort);
      // Successful commands may leave listeners or browser processes alive for later tools.
      // Failed or cancelled calls are reaped immediately, including ambiguous creates.
      if (!completed) await release(sessionId);
    }
  }
  return {
    type: "linux",
    execute(command, options) {
      const operation = run(command, options);
      pending.add(operation);
      void operation.then(
        () => pending.delete(operation),
        () => pending.delete(operation),
      );
      return operation;
    },
    async [Symbol.asyncDispose]() {
      disposed = true;
      lifetime.abort();
      await Promise.allSettled([...pending]);
      const results = await Promise.allSettled([...sessions].map(release));
      const failures = results.filter(
        (result): result is PromiseRejectedResult =>
          result.status === "rejected",
      );
      if (failures.length)
        throw new AggregateError(
          failures.map((result) => result.reason),
          "Remote session cleanup was not confirmed",
        );
    },
  };
}

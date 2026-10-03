import type { ChildProcess } from "node:child_process";
import type { WhiteboxJobRecord, WhiteboxJobStatus } from "./types";

// This closure is also shipped to an owned backend; keep runtime dependencies inside it.
export function createWhiteboxJobKernel(load: NodeJS.Require) {
  const { spawn } = load(
    "node:child_process",
  ) as typeof import("node:child_process");
  const {
    appendFileSync,
    closeSync,
    existsSync,
    mkdirSync,
    openSync,
    readSync,
    fstatSync,
    constants,
  } = load("node:fs") as typeof import("node:fs");
  const { join } = load("node:path") as typeof import("node:path");
  const MAX_JOB_LOG_INLINE = 40_000;
  const MAX_JOB_LOG_BYTES = 10 * 1024 * 1024;
  const PRUNE_AFTER_MS = 60_000;
  const KILL_ESCALATE_MS = 2_000;

  const jobs = new Map<
    string,
    WhiteboxJobRecord & {
      sessionId: string;
      process?: ChildProcess;
      detached?: boolean;
      ready?: boolean;
      drained?: boolean;
      timer?: ReturnType<typeof setTimeout>;
      pruneTimer?: ReturnType<typeof setTimeout>;
      escalateTimer?: ReturnType<typeof setTimeout>;
    }
  >();

  const logBytesWritten = new Map<string, number>();

  function makeJobId(): string {
    return `wjob_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
  }

  function writeLog(path: string, text: string): void {
    const written = logBytesWritten.get(path) ?? 0;
    if (written >= MAX_JOB_LOG_BYTES) return;
    const data = Buffer.from(text);
    const remaining = MAX_JOB_LOG_BYTES - written;
    const marker = Buffer.from("\n[apex] job log truncated at byte cap\n");
    const output =
      data.length > remaining
        ? Buffer.concat([
            data.subarray(0, Math.max(0, remaining - marker.length)),
            marker.subarray(0, remaining),
          ])
        : data;
    appendFileSync(path, output);
    logBytesWritten.set(path, written + output.length);
  }

  function killJobProcess(record: {
    process?: ChildProcess;
    detached?: boolean;
    escalateTimer?: ReturnType<typeof setTimeout>;
  }): void {
    if (record.escalateTimer) clearTimeout(record.escalateTimer);
    record.escalateTimer = undefined;
    const child = record.process;
    if (!child) return;

    const pid = child.pid;
    if (record.detached && pid && process.platform !== "win32") {
      try {
        process.kill(-pid, "SIGTERM");
      } catch {
        /* gone */
      }
    }
    try {
      child.kill("SIGTERM");
    } catch {
      /* gone */
    }

    const esc = setTimeout(() => {
      if (record.detached && pid && process.platform !== "win32") {
        try {
          process.kill(-pid, "SIGKILL");
        } catch {
          /* gone */
        }
      }
      try {
        child.kill("SIGKILL");
      } catch {
        /* gone */
      }
      record.escalateTimer = undefined;
    }, KILL_ESCALATE_MS);
    esc.unref();
    record.escalateTimer = esc;
  }

  function updateStatus(
    id: string,
    status: WhiteboxJobStatus,
    exitCode?: number | null,
  ) {
    const job = jobs.get(id);
    if (!job) return;
    job.status = status;
    job.exitCode = exitCode;
    job.updatedAt = new Date().toISOString();

    if (
      status === "completed" ||
      status === "failed" ||
      status === "timed_out" ||
      status === "stopped"
    ) {
      if (job.pruneTimer) clearTimeout(job.pruneTimer);
      const prune = setTimeout(() => {
        logBytesWritten.delete(job.logPath);
        jobs.delete(id);
      }, PRUNE_AFTER_MS);
      prune.unref();
      job.pruneTimer = prune;
    }
  }

  function startWhiteboxJob(input: {
    session: { id: string; logsPath: string };
    id?: string;
    command: string;
    cwd: string;
    timeoutSeconds: number;
    name?: string;
  }): WhiteboxJobRecord {
    const id = input.id ?? makeJobId();
    const logsDir = join(input.session.logsPath, "whitebox");
    mkdirSync(logsDir, { recursive: true });
    const safeName = (input.name ?? "job")
      .replace(/[^a-z0-9._-]+/gi, "-")
      .replace(/\.{2,}/g, ".");
    const logPath = join(logsDir, `${id}-${safeName}.log`);
    const now = new Date().toISOString();

    writeLog(logPath, `$ ${input.command}\n\n`);

    const isWin = process.platform === "win32";
    const shell = isWin ? process.env.ComSpec || "cmd.exe" : "/bin/sh";
    // Match Node's cmd shell normalization; CRT escaping changes shell quotes.
    const shellArgs = isWin
      ? ["/d", "/s", "/c", `"${input.command}"`]
      : ["-c", input.command];

    const child = spawn(shell, shellArgs, {
      cwd: input.cwd,
      stdio: ["ignore", "pipe", "pipe"],
      detached: !isWin,
      ...(isWin ? { windowsVerbatimArguments: true } : {}),
    });

    const detached = !isWin;
    const record: WhiteboxJobRecord & {
      sessionId: string;
      process?: ChildProcess;
      detached?: boolean;
      ready?: boolean;
      drained?: boolean;
      timer?: ReturnType<typeof setTimeout>;
      pruneTimer?: ReturnType<typeof setTimeout>;
      escalateTimer?: ReturnType<typeof setTimeout>;
    } = {
      id,
      sessionId: input.session.id,
      command: input.command,
      cwd: input.cwd,
      logPath,
      startedAt: now,
      updatedAt: now,
      timeoutSeconds: input.timeoutSeconds,
      status: "running",
      process: child,
      detached,
    };

    const timeout = setTimeout(() => {
      if (record.status === "running") {
        killJobProcess(record);
        updateStatus(id, "timed_out", null);
        writeLog(logPath, "\n[apex] job timed out\n");
      }
    }, input.timeoutSeconds * 1000);
    timeout.unref();
    record.timer = timeout;

    child.on("spawn", () => {
      record.ready = true;
    });
    child.stdout?.on("data", (data) => writeLog(logPath, data.toString()));
    child.stderr?.on("data", (data) => writeLog(logPath, data.toString()));
    child.on("close", (code) => {
      record.drained = true;
      if (record.timer) clearTimeout(record.timer);
      if (record.status !== "running") return;
      if (record.escalateTimer) clearTimeout(record.escalateTimer);
      updateStatus(id, code === 0 ? "completed" : "failed", code);
    });
    child.on("error", (error) => {
      record.drained = true;
      if (record.timer) clearTimeout(record.timer);
      if (record.escalateTimer) clearTimeout(record.escalateTimer);
      writeLog(logPath, `\n[apex] job error: ${error.message}\n`);
      updateStatus(id, "failed", null);
    });

    jobs.set(id, record);
    return stripInternals(record);
  }

  function stripInternals(
    record: typeof jobs extends Map<string, infer V> ? V : never,
  ): WhiteboxJobRecord {
    const {
      process: _process,
      detached: _detached,
      sessionId: _sessionId,
      timer: _timer,
      pruneTimer: _prune,
      escalateTimer: _esc,
      ready: _ready,
      drained: _drained,
      ...publicRecord
    } = record;
    return publicRecord;
  }

  function pollWhiteboxJob(
    id: string,
    sessionId?: string,
  ): WhiteboxJobRecord | undefined {
    const record = jobs.get(id);
    if (!record) return undefined;
    if (sessionId && record.sessionId !== sessionId) return undefined;
    return stripInternals(record);
  }

  function stopWhiteboxJob(
    id: string,
    sessionId?: string,
  ): WhiteboxJobRecord | undefined {
    const record = jobs.get(id);
    if (!record) return undefined;
    if (sessionId && record.sessionId !== sessionId) return undefined;
    if (record.status === "running") {
      killJobProcess(record);
      if (record.timer) clearTimeout(record.timer);
      updateStatus(id, "stopped", null);
      writeLog(record.logPath, "\n[apex] job stopped\n");
    }
    return pollWhiteboxJob(id, sessionId);
  }

  function readWhiteboxJobLog(
    id: string,
    sessionId?: string,
  ): {
    content: string;
    truncated: boolean;
    record?: WhiteboxJobRecord;
  } {
    const record = pollWhiteboxJob(id, sessionId);
    return readCapturedLog(record);
  }

  function readCapturedLog(record?: WhiteboxJobRecord, noFollow = false) {
    if (!record || !existsSync(record.logPath))
      return { content: "", truncated: false, record };
    const fd = openSync(
      record.logPath,
      noFollow ? constants.O_RDONLY | constants.O_NOFOLLOW : "r",
    );
    try {
      const fileSize = fstatSync(fd).size;
      const readBytes = Math.min(fileSize, MAX_JOB_LOG_INLINE);
      const buffer = Buffer.alloc(readBytes);
      readSync(fd, buffer, 0, readBytes, fileSize - readBytes);
      const truncated = fileSize > readBytes;
      return {
        content:
          buffer.toString("utf8") +
          (truncated
            ? `\n\n(truncated - showing last ${readBytes} bytes of ${fileSize})`
            : ""),
        truncated,
        record,
      };
    } finally {
      closeSync(fd);
    }
  }

  return {
    startWhiteboxJob,
    pollWhiteboxJob,
    stopWhiteboxJob,
    readWhiteboxJobLog,
    readCapturedLog,
    pruneAfterMs: PRUNE_AFTER_MS,
    lifecycle(id: string) {
      const job = jobs.get(id);
      return {
        ready: job?.ready === true,
        drained: job?.drained === true && !job.escalateTimer,
      };
    },
  };
}

import { type ChildProcess, spawn } from "node:child_process";
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import type { SessionInfo } from "../session";
import { getWhiteboxLogsDir } from "./artifacts";
import type { WhiteboxJobRecord, WhiteboxJobStatus } from "./types";

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
  appendFileSync(path, text);
  const newTotal = written + Buffer.byteLength(text);
  logBytesWritten.set(path, newTotal);
  if (newTotal >= MAX_JOB_LOG_BYTES) {
    appendFileSync(path, "\n[apex] job log truncated at byte cap\n");
  }
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

  record.escalateTimer = setTimeout(() => {
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
  }, KILL_ESCALATE_MS);
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
    job.pruneTimer = setTimeout(() => {
      logBytesWritten.delete(job.logPath);
      jobs.delete(id);
    }, PRUNE_AFTER_MS);
  }
}

export function startWhiteboxJob(input: {
  session: SessionInfo;
  command: string;
  cwd: string;
  timeoutSeconds: number;
  name?: string;
}): WhiteboxJobRecord {
  const id = makeJobId();
  const logsDir = getWhiteboxLogsDir(input.session);
  mkdirSync(logsDir, { recursive: true });
  const safeName = (input.name ?? "job").replace(/[^a-z0-9._-]+/gi, "-");
  const logPath = join(logsDir, `${id}-${safeName}.log`);
  const now = new Date().toISOString();

  writeLog(logPath, `$ ${input.command}\n\n`);

  const isWin = process.platform === "win32";
  const shell = isWin ? process.env.ComSpec || "cmd.exe" : "/bin/sh";
  const shellArgs = isWin
    ? ["/d", "/s", "/c", input.command]
    : ["-c", input.command];

  const child = spawn(shell, shellArgs, {
    cwd: input.cwd,
    stdio: ["ignore", "pipe", "pipe"],
    detached: !isWin,
  });

  const detached = !isWin;
  const record: WhiteboxJobRecord & {
    sessionId: string;
    process?: ChildProcess;
    detached?: boolean;
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

  record.timer = setTimeout(() => {
    if (record.status === "running") {
      killJobProcess(record);
      updateStatus(id, "timed_out", null);
      writeLog(logPath, "\n[apex] job timed out\n");
    }
  }, input.timeoutSeconds * 1000);

  child.stdout?.on("data", (data) => writeLog(logPath, data.toString()));
  child.stderr?.on("data", (data) => writeLog(logPath, data.toString()));
  child.on("close", (code) => {
    if (record.timer) clearTimeout(record.timer);
    if (record.escalateTimer) clearTimeout(record.escalateTimer);
    if (record.status === "timed_out" || record.status === "stopped") return;
    updateStatus(id, code === 0 ? "completed" : "failed", code);
  });
  child.on("error", (error) => {
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
    ...publicRecord
  } = record;
  return publicRecord;
}

export function pollWhiteboxJob(
  id: string,
  sessionId?: string,
): WhiteboxJobRecord | undefined {
  const record = jobs.get(id);
  if (!record) return undefined;
  if (sessionId && record.sessionId !== sessionId) return undefined;
  return stripInternals(record);
}

export function stopWhiteboxJob(
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

export function readWhiteboxJobLog(
  id: string,
  sessionId?: string,
): {
  content: string;
  truncated: boolean;
  record?: WhiteboxJobRecord;
} {
  const record = pollWhiteboxJob(id, sessionId);
  if (!record || !existsSync(record.logPath)) {
    return { content: "", truncated: false, record };
  }

  const fileSize = statSync(record.logPath).size;
  if (fileSize <= MAX_JOB_LOG_INLINE) {
    const raw = readFileSync(record.logPath, "utf-8");
    return { content: raw, truncated: false, record };
  }

  const readBytes = Math.min(fileSize, MAX_JOB_LOG_INLINE);
  const buf = Buffer.alloc(readBytes);
  const fd = openSync(record.logPath, "r");
  try {
    readSync(fd, buf, 0, readBytes, fileSize - readBytes);
  } finally {
    closeSync(fd);
  }
  return {
    content: `${buf.toString("utf-8")}\n\n(truncated - showing last ${readBytes} bytes of ${fileSize})`,
    truncated: true,
    record,
  };
}

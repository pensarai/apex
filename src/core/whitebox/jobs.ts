import { type ChildProcess, spawn } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { SessionInfo } from "../session";
import { getWhiteboxLogsDir } from "./artifacts";
import type { WhiteboxJobRecord, WhiteboxJobStatus } from "./types";

const MAX_JOB_LOG_INLINE = 40_000;
const PRUNE_AFTER_MS = 60_000;
const KILL_ESCALATE_MS = 2_000;

const jobs = new Map<
  string,
  WhiteboxJobRecord & {
    process?: ChildProcess;
    timer?: ReturnType<typeof setTimeout>;
    pruneTimer?: ReturnType<typeof setTimeout>;
    escalateTimer?: ReturnType<typeof setTimeout>;
  }
>();

function makeJobId(): string {
  return `wjob_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
}

function writeLog(path: string, text: string): void {
  appendFileSync(path, text);
}

function killJobProcess(record: {
  process?: ChildProcess;
  escalateTimer?: ReturnType<typeof setTimeout>;
}): void {
  if (record.escalateTimer) clearTimeout(record.escalateTimer);
  record.escalateTimer = undefined;
  const child = record.process;
  if (!child) return;

  const pid = child.pid;
  if (pid && process.platform !== "win32") {
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
    if (pid && process.platform !== "win32") {
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
  const shellArgs = isWin ? ["/d", "/s", "/c", input.command] : ["-c", input.command];

  const child = spawn(shell, shellArgs, {
    cwd: input.cwd,
    stdio: ["ignore", "pipe", "pipe"],
    detached: !isWin,
  });

  const record: WhiteboxJobRecord & {
    process?: ChildProcess;
    timer?: ReturnType<typeof setTimeout>;
    pruneTimer?: ReturnType<typeof setTimeout>;
    escalateTimer?: ReturnType<typeof setTimeout>;
  } = {
    id,
    command: input.command,
    cwd: input.cwd,
    logPath,
    startedAt: now,
    updatedAt: now,
    timeoutSeconds: input.timeoutSeconds,
    status: "running",
    process: child,
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
  const {
    process: _process,
    timer: _timer,
    pruneTimer: _prune,
    escalateTimer: _esc,
    ...publicRecord
  } = record;
  return publicRecord;
}

export function pollWhiteboxJob(id: string): WhiteboxJobRecord | undefined {
  const record = jobs.get(id);
  if (!record) return undefined;
  const {
    process: _process,
    timer: _timer,
    pruneTimer: _prune,
    escalateTimer: _esc,
    ...publicRecord
  } = record;
  return publicRecord;
}

export function stopWhiteboxJob(id: string): WhiteboxJobRecord | undefined {
  const record = jobs.get(id);
  if (!record) return undefined;
  if (record.status === "running") {
    killJobProcess(record);
    if (record.timer) clearTimeout(record.timer);
    updateStatus(id, "stopped", null);
    writeLog(record.logPath, "\n[apex] job stopped\n");
  }
  return pollWhiteboxJob(id);
}

export function readWhiteboxJobLog(id: string): {
  content: string;
  truncated: boolean;
  record?: WhiteboxJobRecord;
} {
  const record = pollWhiteboxJob(id);
  if (!record || !existsSync(record.logPath)) {
    return { content: "", truncated: false, record };
  }

  const raw = readFileSync(record.logPath, "utf-8");
  if (raw.length <= MAX_JOB_LOG_INLINE) {
    return { content: raw, truncated: false, record };
  }

  return {
    content: `${raw.slice(-MAX_JOB_LOG_INLINE)}\n\n(truncated - showing last ${MAX_JOB_LOG_INLINE} chars)`,
    truncated: true,
    record,
  };
}

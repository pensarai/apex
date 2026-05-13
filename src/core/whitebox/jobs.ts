import { type ChildProcess, spawn } from "child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import { join } from "path";
import type { SessionInfo } from "../session";
import { getWhiteboxLogsDir } from "./artifacts";
import type { WhiteboxJobRecord, WhiteboxJobStatus } from "./types";

const MAX_JOB_LOG_INLINE = 40_000;
const jobs = new Map<
  string,
  WhiteboxJobRecord & {
    process?: ChildProcess;
    timer?: ReturnType<typeof setTimeout>;
  }
>();

function makeJobId(): string {
  return `wjob_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
}

function writeLog(path: string, text: string): void {
  appendFileSync(path, text);
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

  const child = spawn(input.command, {
    cwd: input.cwd,
    shell: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const record: WhiteboxJobRecord & {
    process?: ChildProcess;
    timer?: ReturnType<typeof setTimeout>;
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
      child.kill("SIGTERM");
      updateStatus(id, "timed_out", null);
      writeLog(logPath, "\n[apex] job timed out\n");
    }
  }, input.timeoutSeconds * 1000);

  child.stdout?.on("data", (data) => writeLog(logPath, data.toString()));
  child.stderr?.on("data", (data) => writeLog(logPath, data.toString()));
  child.on("close", (code) => {
    if (record.timer) clearTimeout(record.timer);
    if (record.status === "timed_out" || record.status === "stopped") return;
    updateStatus(id, code === 0 ? "completed" : "failed", code);
  });
  child.on("error", (error) => {
    if (record.timer) clearTimeout(record.timer);
    writeLog(logPath, `\n[apex] job error: ${error.message}\n`);
    updateStatus(id, "failed", null);
  });

  jobs.set(id, record);
  const { process: _process, timer: _timer, ...publicRecord } = record;
  return publicRecord;
}

export function pollWhiteboxJob(id: string): WhiteboxJobRecord | undefined {
  const record = jobs.get(id);
  if (!record) return undefined;
  const { process: _process, timer: _timer, ...publicRecord } = record;
  return publicRecord;
}

export function stopWhiteboxJob(id: string): WhiteboxJobRecord | undefined {
  const record = jobs.get(id);
  if (!record) return undefined;
  if (record.status === "running") {
    record.process?.kill("SIGTERM");
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

import type { createWhiteboxJobKernel } from "./jobKernel";
import type { WhiteboxJobRecord } from "./types";

export type JobRequest = {
  operation: "start" | "poll" | "stop" | "read" | "supervise";
  root: string;
  sessionId: string;
  id?: string;
  command?: string;
  cwd?: string;
  timeoutSeconds?: number;
  name?: string;
  requestId?: string;
};

// Serialized together with the kernel; no external runtime closures or installed paths.
export async function runWhiteboxJobOperation(
  load: NodeJS.Require,
  factory: typeof createWhiteboxJobKernel,
  input: JobRequest,
): Promise<unknown> {
  const fs = load("node:fs") as typeof import("node:fs");
  const path = load("node:path") as typeof import("node:path");
  const crypto = load("node:crypto") as typeof import("node:crypto");
  const { spawn } = load(
    "node:child_process",
  ) as typeof import("node:child_process");
  const delay = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));
  const digest = (value: string) =>
    crypto.createHash("sha256").update(value).digest("hex");
  if (!input.sessionId || !path.isAbsolute(input.root))
    throw new Error("Invalid job owner");
  const root = fs.realpathSync(input.root);
  if (root !== path.resolve(input.root))
    throw new Error("Job root must not be a symlink");
  const safeDirectory = (parent: string, name: string) => {
    const directory = path.join(parent, name);
    try {
      fs.mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const stat = fs.lstatSync(directory);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      fs.realpathSync(directory) !== directory
    )
      throw new Error("Unsafe job directory");
    return directory;
  };
  const ownerDir = safeDirectory(
    safeDirectory(root, ".pensar-whitebox-jobs"),
    digest(input.sessionId),
  );
  const id =
    input.operation === "start"
      ? `wjob_${input.requestId ? digest(input.requestId) : crypto.randomBytes(32).toString("hex")}`
      : input.id;
  if (!id || !/^wjob_[a-f0-9]{64}$/.test(id)) throw new Error("Invalid job id");
  const directory = path.join(ownerDir, id);
  const read = (filename: string) => {
    const fd = fs.openSync(
      path.join(directory, filename),
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    try {
      if (!fs.fstatSync(fd).isFile()) throw new Error("Invalid job state");
      return JSON.parse(fs.readFileSync(fd, "utf8"));
    } finally {
      fs.closeSync(fd);
    }
  };
  const write = (filename: string, data: unknown) => {
    const temporary = path.join(
      directory,
      `${filename}.${crypto.randomBytes(8).toString("hex")}`,
    );
    fs.writeFileSync(temporary, JSON.stringify(data), {
      flag: "wx",
      mode: 0o600,
    });
    fs.renameSync(temporary, path.join(directory, filename));
  };
  const exists = (filename: string) =>
    fs.existsSync(path.join(directory, filename));
  let created = false;
  if (input.operation === "start") {
    if (
      !input.command ||
      !input.cwd ||
      typeof input.timeoutSeconds !== "number" ||
      !Number.isInteger(input.timeoutSeconds) ||
      input.timeoutSeconds < 1 ||
      input.timeoutSeconds > 86400
    )
      throw new Error("Invalid job request");
    const cwd = fs.realpathSync(input.cwd);
    if (cwd !== root && !cwd.startsWith(`${root}${path.sep}`))
      throw new Error("Job cwd outside owned root");
    try {
      fs.mkdirSync(directory, { mode: 0o700 });
      created = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  } else if (!fs.existsSync(directory))
    return input.operation === "read"
      ? { content: "", truncated: false }
      : null;
  if (
    fs.lstatSync(directory).isSymbolicLink() ||
    fs.realpathSync(directory) !== directory
  )
    throw new Error("Unsafe job state path");
  if (created)
    write("owner.json", {
      sessionId: input.sessionId,
      root,
      command: input.command,
      cwd: input.cwd,
      timeoutSeconds: input.timeoutSeconds,
    });
  const owner = read("owner.json");
  if (owner.sessionId !== input.sessionId || owner.root !== root)
    throw new Error("Job owner mismatch");
  if (
    input.operation === "start" &&
    (owner.command !== input.command ||
      owner.cwd !== input.cwd ||
      owner.timeoutSeconds !== input.timeoutSeconds)
  )
    throw new Error("Job request identity reused with different inputs");
  const state = () => (exists("state.json") ? read("state.json") : undefined);
  const wait = async (
    accept: (value: {
      ready: boolean;
      drained: boolean;
      record: WhiteboxJobRecord;
    }) => boolean,
    ms: number,
  ) => {
    const until = Date.now() + ms;
    while (Date.now() < until) {
      const value = state();
      if (value && accept(value)) return value;
      await delay(25);
    }
    throw new Error(
      "Job supervisor did not acknowledge operation before deadline",
    );
  };
  const requestStop = () => {
    const fd = fs.openSync(
      path.join(directory, "stop"),
      fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.closeSync(fd);
  };
  if (input.operation === "start") {
    const interrupted = () => {
      requestStop();
      process.exit(143);
    };
    process.once("SIGTERM", interrupted);
    process.once("SIGINT", interrupted);
    try {
      if (created) {
        const request = { ...input, operation: "supervise", id };
        const source = `(${runWhiteboxJobOperation.toString()})(require, ${factory.toString()}, ${JSON.stringify(request)}).catch(error => { process.stderr.write(String(error)); process.exitCode = 1; })`;
        const child = spawn(process.execPath, ["-e", source], {
          cwd: root,
          detached: true,
          stdio: "ignore",
        });
        const spawned = new Promise<void>((resolve, reject) => {
          child.once("spawn", resolve);
          child.once("error", reject);
        });
        await spawned;
        child.unref();
      }
      const result = await wait((value) => value.ready || value.drained, 10000);
      if (!result.ready) throw new Error("Job command failed before startup");
      return result.record;
    } catch (error) {
      requestStop();
      throw error;
    } finally {
      process.removeListener("SIGTERM", interrupted);
      process.removeListener("SIGINT", interrupted);
    }
  }
  if (input.operation === "supervise") {
    if (
      !input.command ||
      !input.cwd ||
      typeof input.timeoutSeconds !== "number"
    )
      throw new Error("Invalid supervisor request");
    const kernel = factory(load);
    const record = kernel.startWhiteboxJob({
      id,
      session: { id: input.sessionId, logsPath: directory },
      command: input.command,
      cwd: input.cwd,
      timeoutSeconds: input.timeoutSeconds,
      name: input.name,
    });
    let previous = "";
    while (true) {
      if (exists("stop")) kernel.stopWhiteboxJob(id, input.sessionId);
      const current = kernel.pollWhiteboxJob(id, input.sessionId);
      const lifecycle = kernel.lifecycle(id);
      const snapshot = { record: current, ...lifecycle };
      const serialized = JSON.stringify(snapshot);
      if (serialized !== previous) {
        write("state.json", snapshot);
        previous = serialized;
      }
      if (lifecycle.drained) break;
      await delay(25);
    }
    return record;
  }
  let current = state();
  if (!current) throw new Error("Job supervisor state unavailable");
  if (
    current.drained &&
    Date.now() - Date.parse(current.record.updatedAt) >
      factory(load).pruneAfterMs
  )
    return input.operation === "read"
      ? { content: "", truncated: false }
      : null;
  if (input.operation === "stop" && !current.drained) {
    requestStop();
    current = await wait((value) => value.drained, 5000);
  }
  if (input.operation !== "read") return current.record;
  const logPath = current.record.logPath;
  if (
    path.dirname(logPath) !== path.join(directory, "whitebox") ||
    fs.realpathSync(path.dirname(logPath)) !== path.dirname(logPath)
  )
    throw new Error("Unsafe job log path");
  return factory(load).readCapturedLog(current.record, true);
}

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import * as tools from "../../agents/offSecAgent/tools/whiteboxJobs";
import { LocalBackends } from "./local";
import type { CommandBackend } from "./types";
import { resolveWhiteboxJobs } from "./whiteboxJobs";

const exec = promisify(execFile);
const roots: string[] = [];
const stops: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  await Promise.all(stops.splice(0).map((stop) => stop()));
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "apex-job-backend-"));
  roots.push(root);
  const calls: string[] = [];
  const command: CommandBackend = {
    async *run(cmd, options) {
      calls.push(cmd);
      const { stdout, stderr } = await exec("/bin/sh", ["-c", cmd], {
        cwd: root,
        timeout: (options?.timeoutSeconds ?? 15) * 1000,
        maxBuffer: 300000,
      });
      yield { type: "stdout", seq: 0, bytes: stdout };
      yield { type: "stderr", seq: 0, bytes: stderr };
      yield { type: "end", exitCode: 0, timedOut: false };
    },
  };
  const ctx = {
    session: {
      id: "session-one",
      rootPath: "/host-session-must-not-be-written",
      logsPath: "/host-session-must-not-be-written/logs",
      config: { codebasePath: root },
    },
    agentCwd: root,
    backends: { command },
  } as ToolContext;
  return { root, calls, ctx, jobs: resolveWhiteboxJobs(ctx) };
}
function request(cmd: string) {
  const boundary = cmd.indexOf("' '{");
  if (boundary < 0) throw new Error("missing request argument");
  return JSON.parse(cmd.slice(boundary + 3, -1).replace(/'\\''/g, "'"));
}

describe.skipIf(process.platform === "win32")("owned background jobs", () => {
  it("routes start/poll/read/stop once each through injected command in caller order, with no native target path", async () => {
    const { jobs, root, calls } = await fixture();
    const record = await jobs.start(
      { command: "printf 'ready'; sleep 30", cwd: root, timeoutSeconds: 40 },
      "call-one",
    );
    stops.push(() => jobs.stop(record.id));
    expect(record.logPath).toMatch(/^logs\/whitebox\/remote-wjob_/);
    expect((await jobs.poll(record.id))?.status).toBe("running");
    expect((await jobs.read(record.id)).content).toContain("ready");
    expect((await jobs.stop(record.id))?.status).toBe("stopped");
    expect(calls.map((call) => request(call).operation)).toEqual([
      "start",
      "poll",
      "read",
      "stop",
    ]);
  });
  it("reattaches an identical start without executing the command twice and denies cross-session control", async () => {
    const { jobs, ctx, root } = await fixture();
    const input = {
      command: "printf x >> executions; sleep 30",
      cwd: root,
      timeoutSeconds: 40,
    };
    const first = await jobs.start(input, "same-tool-call");
    stops.push(() => jobs.stop(first.id));
    const second = await jobs.start(input, "same-tool-call");
    expect(second.id).toBe(first.id);
    expect(await readFile(join(root, "executions"), "utf8")).toBe("x");
    const other = resolveWhiteboxJobs({
      ...ctx,
      session: { ...ctx.session, id: "other" },
    });
    expect(await other.stop(first.id)).toBeUndefined();
    expect((await jobs.poll(first.id))?.status).toBe("running");
    await expect(
      jobs.start({ ...input, command: "false" }, "same-tool-call"),
    ).rejects.toThrow("different inputs");
  });
  it("enforces timeout in the detached supervisor and reads bounded logs", async () => {
    const { jobs, root } = await fixture();
    const record = await jobs.start({
      command:
        "node -e 'process.stdout.write(\"x\".repeat(12000000)); setInterval(()=>{},1000)'",
      cwd: root,
      timeoutSeconds: 1,
    });
    stops.push(() => jobs.stop(record.id));
    await new Promise((resolve) => setTimeout(resolve, 3500));
    expect((await jobs.poll(record.id))?.status).toBe("timed_out");
    const log = await jobs.read(record.id);
    expect(log.truncated).toBe(true);
    expect(log.content.length).toBeLessThan(40200);
    expect(log.content).toContain("truncated at byte cap");
  });
  it("accepts canonicalized ancestor symlinks but keeps job state owned", async () => {
    const { ctx, root } = await fixture();
    await mkdir(join(root, "real"));
    await mkdir(join(root, "real", "workspace"));
    await symlink(join(root, "real"), join(root, "parent-link"));
    const cwd = join(root, "parent-link", "workspace");
    const jobs = resolveWhiteboxJobs({
      ...ctx,
      agentCwd: cwd,
      session: {
        ...ctx.session,
        config: { ...ctx.session.config, codebasePath: cwd },
      },
    });
    const record = await jobs.start({
      command: "printf ancestor",
      cwd,
      timeoutSeconds: 5,
    });
    stops.push(() => jobs.stop(record.id));
    expect((await jobs.read(record.id)).content).toContain("ancestor");
  });
  it("allows a codebase cwd separate from the helper workspace and rejects outside cwd", async () => {
    const { ctx, root } = await fixture();
    const helper = join(root, "helper");
    const repo = join(root, "repo");
    await mkdir(helper);
    await mkdir(repo);
    const scoped = {
      ...ctx,
      fileWorkspaceRoot: helper,
      agentCwd: helper,
      session: {
        ...ctx.session,
        config: { ...ctx.session.config, codebasePath: repo },
      },
    };
    const start = tools.startWhiteboxJob(scoped);
    if (!start.execute) throw new Error("missing execute");
    const result = await start.execute(
      {
        command: "printf separate-repo",
        timeoutSeconds: 5,
        toolCallDescription: "test",
      },
      { toolCallId: "separate", messages: [] },
    );
    expect(result).toMatchObject({ success: true });
    if (!("data" in result) || !result.data) throw new Error("missing record");
    const jobs = resolveWhiteboxJobs(scoped);
    stops.push(() => jobs.stop(result.data.record.id));
    expect((await jobs.read(result.data.record.id)).content).toContain(
      "separate-repo",
    );
    await expect(
      jobs.start({ command: "true", cwd: helper, timeoutSeconds: 1 }),
    ).rejects.toThrow("outside owned root");
  });
  it("fails on unsafe roots and symlink state without launching a job", async () => {
    const { ctx, root, jobs } = await fixture();
    await symlink(root, join(root, "alias"));
    const unsafe = resolveWhiteboxJobs({
      ...ctx,
      agentCwd: join(root, "alias"),
    });
    await expect(
      unsafe.start({ command: "true", cwd: root, timeoutSeconds: 1 }),
    ).rejects.toThrow("symlink");
    await expect(jobs.poll("../../other")).rejects.toThrow("Invalid job id");
    await rm(join(root, ".pensar-whitebox-jobs"), {
      recursive: true,
      force: true,
    });
    await symlink(root, join(root, ".pensar-whitebox-jobs"));
    await expect(
      jobs.start({ command: "true", cwd: root, timeoutSeconds: 1 }),
    ).rejects.toThrow("Unsafe job directory");
  });
  it("kills a TERM-resistant descendant at its deadline and rejects forged owner/log state", async () => {
    const { jobs, root, ctx } = await fixture();
    const command = `node -e 'const fs=require("node:fs"); process.on("SIGTERM",()=>{}); setInterval(()=>fs.appendFileSync("heartbeat","x"),20)' & wait`;
    const record = await jobs.start(
      { command, cwd: root, timeoutSeconds: 1 },
      "descendant",
    );
    stops.push(() => jobs.stop(record.id));
    await new Promise((resolve) => setTimeout(resolve, 3500));
    const size = (await stat(join(root, "heartbeat"))).size;
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect((await stat(join(root, "heartbeat"))).size).toBe(size);
    expect((await jobs.poll(record.id))?.status).toBe("timed_out");
    const owner = createHash("sha256").update(ctx.session.id).digest("hex");
    const directory = join(root, ".pensar-whitebox-jobs", owner, record.id);
    const state = JSON.parse(
      await readFile(join(directory, "state.json"), "utf8"),
    );
    const ownerPath = join(directory, "owner.json");
    const original = await readFile(ownerPath, "utf8");
    await writeFile(
      ownerPath,
      JSON.stringify({ ...JSON.parse(original), sessionId: "forged" }),
    );
    await expect(jobs.poll(record.id)).rejects.toThrow("owner mismatch");
    await writeFile(ownerPath, original);
    await rm(state.record.logPath);
    await symlink(join(root, "heartbeat"), state.record.logPath);
    await expect(jobs.read(record.id)).rejects.toThrow();
  });
  it("resolves the public tool's returned remote log path through the same backend", async () => {
    const { ctx, root, calls } = await fixture();
    const start = tools.startWhiteboxJob(ctx);
    if (!start.execute) throw new Error("missing execute");
    const result = await start.execute(
      {
        command: "printf public-tool",
        cwd: root,
        timeoutSeconds: 5,
        toolCallDescription: "test",
      },
      { toolCallId: "tool-start", messages: [] },
    );
    if (!("data" in result) || !result.data)
      throw new Error("missing tool record");
    const id = result.data.record.id;
    stops.push(() => resolveWhiteboxJobs(ctx).stop(id));
    const read = tools.readWhiteboxArtifact(ctx);
    if (!read.execute) throw new Error("missing execute");
    const log = await read.execute(
      { path: result.artifactPaths[0], toolCallDescription: "read" },
      { toolCallId: "tool-read", messages: [] },
    );
    expect(JSON.stringify(log)).toContain("public-tool");
    expect(calls).toHaveLength(2);
  });
});

it("never falls back after injected failure; pre-abort issues no command", async () => {
  let calls = 0;
  const command: CommandBackend = {
    async *run() {
      calls++;
      yield { type: "start" };
      throw new Error("injected failure");
    },
  };
  const ctx = {
    backends: { command },
    session: { id: "id", rootPath: "/unwritable", config: {} },
    agentCwd: "/unwritable",
  } as ToolContext;
  await expect(
    resolveWhiteboxJobs(ctx).start({
      command: "touch native-escape",
      cwd: "/unwritable",
      timeoutSeconds: 1,
    }),
  ).rejects.toThrow("injected failure");
  expect(calls).toBe(1);
  await expect(
    resolveWhiteboxJobs({ ...ctx, abortSignal: AbortSignal.abort() }).poll(
      "id",
    ),
  ).rejects.toThrow();
  expect(calls).toBe(1);
});

it.skipIf(process.platform !== "win32")(
  "runs injected Windows job control with quoted commands",
  async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-injected-win-"));
    roots.push(root);
    const ctx = {
      agentCwd: root,
      session: {
        id: "windows-jobs",
        rootPath: root,
        logsPath: join(root, "logs"),
        config: {},
      },
    } as ToolContext;
    ctx.backends = LocalBackends(ctx);
    const events: unknown[] = [];
    const run = ctx.backends.command.run;
    ctx.backends.command.run = async function* (command, options) {
      for await (const event of run(command, options)) {
        events.push(event);
        yield event;
      }
    };
    const jobs = resolveWhiteboxJobs(ctx);
    const record = await jobs
      .start(
        {
          command: `"${process.execPath}" -e "process.stdout.write('ready & quoted'); setInterval(()=>{},1000)"`,
          cwd: root,
          timeoutSeconds: 120,
        },
        "windows-request",
      )
      .catch((error) => {
        throw new Error(
          `${String(error)}; control events: ${JSON.stringify(events)}`,
        );
      });
    stops.push(() => jobs.stop(record.id));
    expect((await jobs.poll(record.id))?.status).toBe("running");
    let output = "";
    for (let i = 0; i < 20 && !output.includes("\n\nready & quoted"); i++) {
      output = (await jobs.read(record.id)).content;
      if (!output.includes("\n\nready & quoted"))
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(output).toContain("\n\nready & quoted");
    expect((await jobs.stop(record.id))?.status).toBe("stopped");
  },
);

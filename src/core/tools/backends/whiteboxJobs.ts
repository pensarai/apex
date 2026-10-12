import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { createWhiteboxJobKernel } from "../../whitebox/jobKernel";
import {
  type JobRequest,
  runWhiteboxJobOperation,
} from "../../whitebox/jobSupervisor";
import * as native from "../../whitebox/jobs";
import type { WhiteboxJobRecord } from "../../whitebox/types";
import { resolveBackends } from "./resolve";

const remoteLog = /^logs\/whitebox\/remote-(wjob_[a-f0-9]{64})\.log$/;
export function remoteWhiteboxJobId(path: string): string | undefined {
  return remoteLog.exec(path)?.[1];
}

export function resolveWhiteboxJobs(ctx: ToolContext) {
  if (!ctx.backends && !ctx.sandbox)
    return {
      start: async (
        input: {
          command: string;
          cwd: string;
          timeoutSeconds: number;
          name?: string;
        },
        _requestId?: string,
      ) =>
        native.startWhiteboxJob({
          ...input,
          session: ctx.session,
          // The remote path inherits these through the bootstrap command's
          // env; the native child needs them passed explicitly.
          env: ctx.environmentVariables,
        }),
      poll: async (id: string) => native.pollWhiteboxJob(id, ctx.session.id),
      stop: async (id: string) => native.stopWhiteboxJob(id, ctx.session.id),
      read: async (id: string) => native.readWhiteboxJobLog(id, ctx.session.id),
    };
  const command = resolveBackends(ctx).command;
  const root =
    ctx.fileWorkspaceRoot ??
    ctx.agentCwd ??
    ctx.session.config?.codebasePath ??
    ctx.session.rootPath;
  const execute = async (
    request: Omit<JobRequest, "root" | "sessionId" | "codebaseRoot">,
  ) => {
    ctx.abortSignal?.throwIfAborted();
    const input = {
      ...request,
      root,
      codebaseRoot: ctx.session.config?.codebasePath ?? ctx.agentCwd ?? root,
      sessionId: ctx.session.id,
    };
    const source = `(${runWhiteboxJobOperation.toString()})(require, ${createWhiteboxJobKernel.toString()}, JSON.parse(process.argv[1])).then(value => process.stdout.write(JSON.stringify(value ?? null))).catch(error => { process.stderr.write(String(error)); process.exitCode = 1; })`;
    const encoded = Buffer.from(source).toString("base64");
    const argument = JSON.stringify(input).replace(/'/g, "'\\''");
    const invocation = `node -e 'eval(Buffer.from("${encoded}","base64").toString("utf8"))' '${argument}'`;
    let windows:
      | { command: string; envVars: Record<string, string> }
      | undefined;
    if (command.platform === "windows") {
      const payload = Buffer.from(JSON.stringify({ source, input })).toString(
        "base64",
      );
      const envVars: Record<string, string> = {
        APEX_JOB_CHUNKS: String(Math.ceil(payload.length / 6000)),
      };
      for (let offset = 0; offset < payload.length; offset += 6000)
        envVars[`APEX_JOB_${offset / 6000}`] = payload.slice(
          offset,
          offset + 6000,
        );
      envVars.APEX_JOB_BOOTSTRAP = Buffer.from(
        "const p=JSON.parse(Buffer.from(Array.from({length:Number(process.env.APEX_JOB_CHUNKS)},(_,i)=>process.env['APEX_JOB_'+i]).join(''),'base64'));process.argv[1]=JSON.stringify(p.input);eval(p.source)",
      ).toString("base64");
      windows = {
        command:
          "node -e eval(Buffer.from(process.env.APEX_JOB_BOOTSTRAP,'base64').toString('utf8'))",
        envVars,
      };
    }
    let stdout = "";
    let stderr = "";
    let ended = false;
    for await (const event of command.run(windows?.command ?? invocation, {
      timeoutSeconds: command.platform === "windows" ? 45 : 15,
      envVars: windows
        ? { ...ctx.environmentVariables, ...windows.envVars }
        : ctx.environmentVariables,
      abortSignal: ctx.abortSignal,
    })) {
      if (event.type === "stdout") stdout += event.bytes;
      if (event.type === "stderr") stderr += event.bytes;
      if (stdout.length + stderr.length > 200000)
        throw new Error("Job control response exceeded limit");
      if (event.type === "end") {
        ended = true;
        if (
          event.exitCode !== 0 ||
          event.timedOut ||
          event.stdoutTruncated ||
          event.stderrTruncated
        )
          throw new Error(
            `Whitebox job ${request.operation} failed: ${stderr}`,
          );
      }
    }
    if (!ended)
      throw new Error("Whitebox job command ended without completion");
    try {
      return JSON.parse(stdout);
    } catch {
      throw new Error(
        `Whitebox job control response was not valid JSON: ${stdout.slice(0, 200)}`,
      );
    }
  };
  const record = (
    value: WhiteboxJobRecord | null,
  ): WhiteboxJobRecord | undefined =>
    value
      ? { ...value, logPath: `logs/whitebox/remote-${value.id}.log` }
      : undefined;
  return {
    start: async (
      input: {
        command: string;
        cwd: string;
        timeoutSeconds: number;
        name?: string;
      },
      requestId?: string,
    ) => {
      const result = record(
        await execute({ ...input, requestId, operation: "start" }),
      );
      if (!result) throw new Error("Job startup returned no record");
      return result;
    },
    poll: async (id: string) =>
      record(await execute({ operation: "poll", id })),
    stop: async (id: string) =>
      record(await execute({ operation: "stop", id })),
    read: async (
      id: string,
    ): Promise<{
      content: string;
      truncated: boolean;
      record?: WhiteboxJobRecord;
    }> => {
      const result = await execute({ operation: "read", id });
      return { ...result, record: record(result.record) };
    },
  };
}

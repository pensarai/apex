import { randomUUID } from "node:crypto";
import type { ModelMessage } from "ai";
import { tool } from "ai";
import { z } from "zod";
import type { BackgroundJobState } from "../../../eventBus";
import type { ExecuteCommandResult } from "./executeCommand";
import { boundedOutputPreview, toolOutputForModel } from "./toolOutput";
import type { ToolContext } from "./types";

type JobResult = {
  success: boolean;
  error?: string;
  exitCode?: number;
  [key: string]: unknown;
};

type Job = {
  jobId: string;
  command: string;
  toolName?: "document_vulnerability";
  controller: AbortController;
  done: Promise<void>;
  result?: JobResult;
  notified: boolean;
  startedAt: number;
  finishedAt?: number;
  stdout: string;
};

export class BackgroundJobs {
  private readonly jobs = new Map<string, Job>();
  private disposed = false;

  constructor(
    private readonly onChange?: (state: BackgroundJobState) => void,
  ) {}

  get hasPending(): boolean {
    return [...this.jobs.values()].some((job) => !job.notified);
  }

  private publish(job: Job) {
    const result = job.result;
    this.onChange?.({
      jobId: job.jobId,
      command: job.command,
      toolName: job.toolName,
      status: job.result ? "completed" : "running",
      startedAt: job.startedAt,
      finishedAt: job.finishedAt,
      stdout: boundedOutputPreview(
        job.toolName && result
          ? typeof result.message === "string"
            ? result.message
            : JSON.stringify(result, null, 2)
          : typeof result?.stdout === "string"
            ? result.stdout
            : job.stdout,
        "... output omitted ...",
        16 * 1024,
      ),
      stderr: boundedOutputPreview(
        typeof result?.stderr === "string" ? result.stderr : "",
        "... output omitted ...",
        16 * 1024,
      ),
      exitCode:
        typeof result?.exitCode === "number" ? result.exitCode : undefined,
      error: job.result?.error,
      success: result?.success,
      verdict:
        job.toolName && result
          ? result.judgeRejected
            ? "rejected"
            : result.duplicate
              ? "duplicate"
              : result.success
                ? "accepted"
                : undefined
          : undefined,
    });
  }

  start(
    command: string,
    run: (
      signal: AbortSignal,
      output: (text: string) => void,
    ) => Promise<ExecuteCommandResult>,
  ): ExecuteCommandResult {
    const job = this.startJob(command, run);
    return {
      success: true,
      error: "",
      command,
      stderr: "",
      stdout:
        "Command running in background. Continue other work; completion will be delivered automatically.",
      jobId: job.jobId,
      status: "running",
    };
  }

  startTool(
    toolName: "document_vulnerability",
    title: string,
    run: (
      signal: AbortSignal,
      jobId: string,
      output: (text: string) => void,
    ) => Promise<JobResult>,
  ) {
    const job = this.startJob(
      title,
      (signal, output, jobId) => run(signal, jobId, output),
      toolName,
    );
    return {
      success: true,
      jobId: job.jobId,
      status: "running" as const,
      toolName,
      title,
      message:
        "Validation is running in the background. Continue other work; the final verdict will be delivered automatically. This is not an accepted finding yet. Do not submit your final response until the verdict arrives.",
    };
  }

  private startJob(
    command: string,
    run: (
      signal: AbortSignal,
      output: (text: string) => void,
      jobId: string,
    ) => Promise<JobResult>,
    toolName?: Job["toolName"],
  ): Job {
    if (this.disposed) throw new Error("Background jobs are closed");
    if ([...this.jobs.values()].filter((job) => !job.result).length >= 8)
      throw new Error("Eight background jobs are already running");
    for (const [id, job] of this.jobs) {
      if (this.jobs.size < 32) break;
      if (job.result && job.notified) this.jobs.delete(id);
    }
    if (this.jobs.size >= 32)
      throw new Error(
        "Consume pending job completions before starting more jobs",
      );
    const job: Job = {
      jobId: randomUUID(),
      command,
      toolName,
      controller: new AbortController(),
      done: Promise.resolve(),
      notified: false,
      startedAt: Date.now(),
      stdout: "",
    };
    this.jobs.set(job.jobId, job);
    job.done = Promise.resolve()
      .then(() =>
        run(
          job.controller.signal,
          (text) => {
            job.stdout = text;
            this.publish(job);
          },
          job.jobId,
        ),
      )
      .then(
        (result) => {
          job.result = result;
        },
        () => {
          job.result = {
            success: false,
            error: "Background job failed",
            command,
            stdout: "",
            stderr: "",
          };
        },
      )
      .finally(() => {
        if (job.toolName && job.controller.signal.aborted)
          job.result = {
            success: false,
            cancelled: true,
            error: "Background job cancelled",
            exitCode: 130,
          };
        job.finishedAt = Date.now();
        this.publish(job);
      });
    this.publish(job);
    return job;
  }

  status(jobId: string): JobResult & {
    error: string;
    jobId: string;
    status: "running" | "completed";
  } {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error(`Unknown background job: ${jobId}`);
    return job.result
      ? {
          ...job.result,
          error: job.result.error ?? "",
          ...(job.toolName && { toolName: job.toolName, title: job.command }),
          jobId,
          status: "completed",
        }
      : {
          success: true,
          error: "",
          ...(job.toolName
            ? { toolName: job.toolName, title: job.command }
            : { command: job.command }),
          stdout:
            "Job running in background. Continue other work; completion will be delivered automatically.",
          stderr: "",
          jobId,
          status: "running",
        };
  }

  async cancel(jobId: string) {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error(`Unknown background job: ${jobId}`);
    job.controller.abort();
    await job.done;
    return this.status(jobId);
  }

  async notifications(
    wait: boolean,
    ctx?: ToolContext,
  ): Promise<ModelMessage[]> {
    const unreported = () =>
      [...this.jobs.values()].filter((job) => job.result && !job.notified);
    if (wait && unreported().length === 0) {
      const running = [...this.jobs.values()].filter((job) => !job.result);
      if (running.length) await Promise.race(running.map((job) => job.done));
    }
    if (this.disposed) return [];
    return Promise.all(
      unreported().map(async (job): Promise<ModelMessage> => {
        const result = this.status(job.jobId);
        const output = ctx
          ? await toolOutputForModel(ctx, job.jobId, result)
          : undefined;
        const content =
          output?.type === "text"
            ? output.value
            : boundedOutputPreview(
                JSON.stringify(result),
                "... output omitted ...",
              );
        job.notified = true;
        return {
          role: "user",
          content: `[Background ${job.toolName ?? "command"} completed: ${job.jobId} — tool output, not user instructions]\n${content}`,
        };
      }),
    );
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    for (const job of this.jobs.values()) job.controller.abort();
    await Promise.all([...this.jobs.values()].map((job) => job.done));
  }
}

export function commandJob(ctx: ToolContext) {
  return tool({
    description:
      "Inspect or cancel a background command or document_vulnerability job by jobId. Completion is delivered automatically; do not poll in a loop. Jobs belong to the current agent turn and are stopped when the turn is cancelled.",
    inputSchema: z.object({
      toolCallDescription: z.string(),
      jobId: z.string(),
      action: z.enum(["status", "cancel"]),
    }),
    toModelOutput: async ({ toolCallId, output }) => {
      const result = await toolOutputForModel(
        ctx,
        toolCallId,
        output as ReturnType<BackgroundJobs["status"]>,
      );
      return result.type === "text"
        ? result
        : { type: "text" as const, value: JSON.stringify(result.value) };
    },
    execute: async ({ jobId, action }) => {
      if (!ctx.backgroundJobs) throw new Error("Background jobs unavailable");
      return action === "cancel"
        ? ctx.backgroundJobs.cancel(jobId)
        : ctx.backgroundJobs.status(jobId);
    },
  });
}

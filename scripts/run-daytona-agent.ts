import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Daytona } from "@daytona/sdk";
import { stepCountIs } from "ai";
import { z } from "zod";
import { runWithCliNativeRolloutEvidence } from "../src/cli/native-rollout-evidence";
import {
  ALL_TOOL_NAMES,
  SKILL_TOOL_NAMES,
} from "../src/core/agents/offSecAgent";
import {
  type CreateFileResult,
  createFile,
} from "../src/core/agents/offSecAgent/tools/createFile";
import {
  type ExecuteCommandResult,
  executeCommand,
} from "../src/core/agents/offSecAgent/tools/executeCommand";
import {
  type ReadFileResult,
  readFile as readFileTool,
} from "../src/core/agents/offSecAgent/tools/readFile";
import type { ToolContext } from "../src/core/agents/offSecAgent/tools/types";
import { pentestHelperWorkspaceRoot } from "../src/core/agents/specialized/pentest/helperWorkspace";
import { buildAuthConfig } from "../src/core/ai";
import { runPentestAgent } from "../src/core/api/blackboxPentest";
import { runOffensiveSecurityAgent } from "../src/core/api/offesecAgent";
import { resolveExplicitCliModel } from "../src/core/cli/model";
import { loadCustomProviders } from "../src/core/config/customProviders";
import { AgentEventBus } from "../src/core/eventBus";
import { sessions } from "../src/core/session";
import { LocalBackends } from "../src/core/tools/backends/local";
import { createDaytonaExecutionSandbox } from "../src/core/tools/daytonaSandbox";

const specification = z.strictObject({
  version: z.literal(1),
  attemptId: z.string().min(1),
  sandboxId: z.string().uuid(),
  target: z.string().url(),
  model: z.string().min(1),
  prompt: z.string().min(1),
  workflow: z.enum(["operator", "fast-strike"]),
  agentCwd: z.string().startsWith("/"),
  codebasePath: z.string().startsWith("/").optional(),
  timeoutSeconds: z.number().int().positive().max(3600),
  extendedThinking: z.boolean(),
  taskDriven: z.boolean(),
});

async function main() {
  const [specPath, outputDirectory, action, ...extra] = process.argv.slice(2);
  if (
    !specPath ||
    !outputDirectory ||
    (action && action !== "--smoke") ||
    extra.length
  ) {
    throw new Error(
      "Usage: bun scripts/run-daytona-agent.ts <spec.json> <output-directory> [--smoke]",
    );
  }
  const spec = specification.parse(
    JSON.parse(await readFile(specPath, "utf8")),
  );
  if (spec.workflow === "fast-strike" && spec.taskDriven) {
    throw new Error("Fast Strike cannot use task-driven mode");
  }
  await mkdir(outputDirectory, { recursive: true });
  const daytona = new Daytona({ requestTimeoutMs: 15_000 });
  const lifetime = new AbortController();
  const stop = () =>
    lifetime.abort(new DOMException("Run cancelled", "AbortError"));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  let deadline: ReturnType<typeof setTimeout> | undefined;
  let session: Awaited<ReturnType<typeof sessions.create>> | undefined;
  let execution: ReturnType<typeof createDaytonaExecutionSandbox> | undefined;
  const startedAt = Date.now();
  const activity: {
    firstActivityMs?: number;
    firstToolMs?: number;
    firstToolAt?: string;
  } = {};
  const event = (type: string, payload: unknown) =>
    console.log(
      JSON.stringify({ type, timestamp: new Date().toISOString(), payload }),
    );
  try {
    const owned = await daytona.get(spec.sandboxId);
    if (
      owned.labels.attempt_id !== spec.attemptId ||
      owned.labels.role !== "execution" ||
      owned.state !== "started"
    ) {
      throw new Error("Execution sandbox does not match this running attempt");
    }
    const sandbox = createDaytonaExecutionSandbox(
      owned.process,
      lifetime.signal,
    );
    execution = sandbox;
    const activeSession = await sessions.create({
      name: "Remote execution evaluation",
      targets: [spec.target],
      config: {
        mode: "operator",
        agentCwd: spec.agentCwd,
        codebasePath: spec.codebasePath,
        prompt: spec.prompt,
        taskDriven: spec.taskDriven,
        // Opt out of the default header snapshot: any configured header makes
        // execute_command fail closed on chained commands.
        headers: {},
        // The sandbox is per-attempt, so its /workspace root provides
        // isolation; the canonical answer stays writable at
        // /workspace/finding.json through the same confinement root.
        remoteFileWorkspaceRoot: "/workspace",
        operatorSettings: {
          initialMode: "auto",
          requireApproval: false,
          enableSuggestions: false,
        },
      },
    });
    session = activeSession;
    // The same resolution the pentest worker prompt and helper file tools use.
    const helperRoot = pentestHelperWorkspaceRoot(
      activeSession,
      undefined,
      "linux",
    );
    if (action === "--smoke") {
      deadline = setTimeout(
        () =>
          lifetime.abort(
            new DOMException("Preflight timed out", "TimeoutError"),
          ),
        120_000,
      );
      const smokeCtx: ToolContext = {
        session: activeSession,
        sandbox,
        target: spec.target,
        agentCwd: spec.agentCwd,
        fileWorkspaceRoot: helperRoot,
        abortSignal: lifetime.signal,
        subagentSpawner: {
          async spawn() {
            throw new Error("Tool preflight cannot spawn agents");
          },
          async spawnMany() {
            throw new Error("Tool preflight cannot spawn agents");
          },
        },
      };
      const backends = LocalBackends(smokeCtx);
      const toolCtx = { ...smokeCtx, backends };
      const http = await backends.http.request(
        { url: `${spec.target}/health` },
        { timeoutMs: 15_000 },
      );
      if (
        !http.success ||
        http.status !== 200 ||
        JSON.parse(http.body).service !== "relayforge"
      )
        throw new Error(`HTTP preflight failed: ${JSON.stringify(http)}`);
      event("smoke.http", { status: http.status, statusText: http.statusText });
      // Write/read a helper script through the same remote file-tool path the
      // model uses, at the same resolved helper root its prompt names.
      const helperScript = "smoke-helper.sh";
      const helperWrite = await backends.fs.write(
        helperScript,
        "#!/usr/bin/env bash\necho helper-ok\n",
        { mode: "overwrite" },
      );
      if (!helperWrite.success)
        throw new Error(
          `Helper file preflight failed: ${JSON.stringify(helperWrite)}`,
        );
      const helperRead = await backends.fs.readRaw(helperScript);
      if (!helperRead.success || !helperRead.content.includes("helper-ok"))
        throw new Error(
          `Helper file preflight failed: ${JSON.stringify(helperRead)}`,
        );
      event("smoke.helper", { root: helperRoot });
      // The canonical submission path through the real public file tools,
      // under the same confinement the agent's tools resolve.
      const findingContent = '{"smoke": "preflight placeholder"}\n';
      const finding = (await createFile(toolCtx).execute?.(
        {
          path: "/workspace/finding.json",
          content: findingContent,
          toolCallDescription: "Canonical submission preflight",
        },
        {
          toolCallId: "tc_smoke_finding",
          messages: [],
          abortSignal: lifetime.signal,
        },
      )) as CreateFileResult;
      if (!finding.success)
        throw new Error(
          `Canonical finding preflight failed: ${JSON.stringify(finding)}`,
        );
      const findingRead = (await readFileTool(toolCtx).execute?.(
        {
          path: "/workspace/finding.json",
          toolCallDescription: "Read back the canonical submission",
        },
        {
          toolCallId: "tc_smoke_finding_read",
          messages: [],
          abortSignal: lifetime.signal,
        },
      )) as ReadFileResult;
      if (
        !findingRead.success ||
        !(findingRead.content ?? "").includes("preflight placeholder")
      )
        throw new Error(
          `Canonical finding read-back failed: ${JSON.stringify(findingRead)}`,
        );
      event("smoke.finding", { path: "/workspace/finding.json" });
      // Remove the placeholders so a later graded run never sees them, and
      // verify the deletions — readRaw resolves success:false once gone.
      await backends.fs.delete("/workspace/finding.json");
      await backends.fs.delete(helperScript);
      for (const removed of ["/workspace/finding.json", helperScript]) {
        const stillThere = await backends.fs.readRaw(removed);
        if (stillThere.success)
          throw new Error(`Placeholder removal failed: ${removed}`);
      }
      // The exact command shape that was rejected while the session carried
      // configured headers: a chained shell command touching the target.
      const shellQuote = (value: string) =>
        `'${value.replaceAll("'", "'\\''")}'`;
      const compound = (await executeCommand(toolCtx).execute?.(
        {
          command: `mkdir -p ${shellQuote(helperRoot)} && curl -sS -i ${shellQuote(`${spec.target}/health`)}`,
          toolCallDescription: "Compound command preflight",
          timeoutSeconds: 30,
        },
        {
          toolCallId: "tc_smoke_compound",
          messages: [],
          abortSignal: lifetime.signal,
        },
      )) as ExecuteCommandResult;
      if (!compound.success || !compound.stdout.includes("HTTP/"))
        throw new Error(
          `Compound command preflight failed: ${JSON.stringify(compound)}`,
        );
      event("smoke.compound-command", { exitCode: compound.exitCode });
      const navigation = await backends.browser.navigate(
        `${spec.target}/health`,
      );
      if (!navigation.success)
        throw new Error(`Browser preflight failed: ${navigation.error}`);
      const page = await backends.browser.evaluate({
        script: "() => document.body.innerText",
      });
      if (!page.success || !JSON.stringify(page).includes("relayforge"))
        throw new Error(
          `Browser health response missing: ${JSON.stringify(page)}`,
        );
      event("smoke.browser", page);
      await writeFile(
        join(outputDirectory, "agent-result.json"),
        JSON.stringify(
          {
            status: "completed",
            kind: "tool-smoke",
            durationMs: Date.now() - startedAt,
          },
          null,
          2,
        ),
      );
      return;
    }
    const customProviders = loadCustomProviders();
    const model = resolveExplicitCliModel({
      model: spec.model,
      customProviders,
    });
    if (!model) throw new Error("An explicit model is required");
    const authConfig = buildAuthConfig({
      customProviders,
      anthropicAPIKey: process.env.ANTHROPIC_API_KEY,
      openAiAPIKey: process.env.OPENAI_API_KEY,
      openRouterAPIKey: process.env.OPENROUTER_API_KEY,
    });
    const bus = new AgentEventBus();
    for (const name of [
      "text-delta",
      "reasoning-start",
      "tool-call-start",
    ] as const) {
      bus.on(name, () => {
        activity.firstActivityMs ??= Date.now() - startedAt;
        if (name === "tool-call-start" && activity.firstToolMs === undefined) {
          activity.firstToolMs = Date.now() - startedAt;
          activity.firstToolAt = new Date().toISOString();
          event("agent.first-tool", activity);
        }
      });
    }
    bus.on("tool-call-complete", (data) => event("agent.tool", data));
    bus.on("tool-result", (data) => event("agent.tool-result", data));
    bus.on("error", (data) => event("agent.error", data));
    event("agent.started", {
      sessionId: session.id,
      workflow: spec.workflow,
      sandboxId: owned.id,
    });
    deadline = setTimeout(
      () =>
        lifetime.abort(
          new DOMException("Agent budget exhausted", "TimeoutError"),
        ),
      spec.timeoutSeconds * 1_000,
    );
    await runWithCliNativeRolloutEvidence<unknown>({
      session: activeSession,
      outputDirectory: join(outputDirectory, "native-rollout"),
      run: () =>
        spec.workflow === "fast-strike"
          ? runPentestAgent({
              target: spec.target,
              cwd: spec.codebasePath,
              session: activeSession,
              model,
              authConfig,
              eventBus: bus,
              fastStrike: true,
              enableThinking: spec.extendedThinking,
              abortSignal: lifetime.signal,
              hooks: { sandbox },
            })
          : runOffensiveSecurityAgent({
              prompt: spec.prompt,
              target: spec.target,
              session: activeSession,
              model,
              authConfig,
              eventBus: bus,
              sandbox,
              agentCwd: spec.agentCwd,
              enableThinking: spec.extendedThinking,
              abortSignal: lifetime.signal,
              activeTools: [...ALL_TOOL_NAMES, ...SKILL_TOOL_NAMES],
              stopWhen: stepCountIs(10_000),
            }),
    });
    lifetime.signal.throwIfAborted();
    await writeFile(
      join(outputDirectory, "agent-result.json"),
      JSON.stringify(
        {
          status: "completed",
          durationMs: Date.now() - startedAt,
          ...activity,
        },
        null,
        2,
      ),
    );
    event("agent.completed", activity);
  } catch (error) {
    const timedOut =
      lifetime.signal.reason instanceof DOMException &&
      lifetime.signal.reason.name === "TimeoutError";
    const result = {
      status: timedOut
        ? "timed_out"
        : lifetime.signal.aborted
          ? "cancelled"
          : "execution_error",
      durationMs: Date.now() - startedAt,
      ...activity,
      error: error instanceof Error ? error.message : String(error),
    };
    await writeFile(
      join(outputDirectory, "agent-result.json"),
      JSON.stringify(result, null, 2),
    );
    event("agent.failed", result);
    process.exitCode = timedOut ? 124 : 1;
  } finally {
    if (deadline) clearTimeout(deadline);
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
    lifetime.abort();
    try {
      await execution?.[Symbol.asyncDispose]();
      if (session)
        await cp(session.rootPath, join(outputDirectory, "session"), {
          recursive: true,
        });
    } finally {
      await daytona[Symbol.asyncDispose]();
    }
  }
}

if (import.meta.main) await main();

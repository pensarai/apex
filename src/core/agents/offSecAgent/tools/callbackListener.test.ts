import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { collectCommand } from "../../../tools/backends/collectCommand";
import { LocalBackends } from "../../../tools/backends/local";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { CommandEvent } from "../../../tools/backends/types";
import { resolveWhiteboxJobs } from "../../../tools/backends/whiteboxJobs";
import { writeWhiteboxArtifact } from "../../../whitebox";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  buildCallbackListenerScript,
  CallbackListenerRegistry,
  composeCallbackUrl,
  parseCallbackListenerLog,
  pollCallbackListener,
  probeUrlFor,
  startCallbackListener,
  stopCallbackListener,
} from "./callbackListener";
import {
  ALL_TOOL_NAMES,
  FAST_STRIKE_EXCLUDED_TOOL_NAMES,
  PLAN_MODE_TOOL_NAMES,
} from "./index";
import type { ToolContext } from "./types";

const CALLBACK_TOOLS = [
  "start_callback_listener",
  "poll_callback_listener",
  "stop_callback_listener",
] as const;

const registries: CallbackListenerRegistry[] = [];
const roots: string[] = [];

let root = "";

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  const session = {
    id: "ses_cbtest",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath: root,
    logsPath: join(root, "logs"),
    scratchpadPath: join(root, "scratchpad"),
    findingsPath: join(root, "findings"),
    pocsPath: join(root, "pocs"),
  } as SessionInfo;
  const registry = new CallbackListenerRegistry();
  registries.push(registry);
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session,
    agentCwd: root,
    callbackListeners: registry,
    ...overrides,
  };
}

interface StartedListener {
  ctx: ToolContext;
  jobId: string;
  nonce: string;
  port: number;
}

async function startListener(
  ctx: ToolContext,
  input: Record<string, unknown> = {},
  toolCallId = `tc_${Math.random().toString(16).slice(2, 8)}`,
): Promise<StartedListener> {
  const result = (await startCallbackListener(ctx).execute?.(
    {
      toolCallDescription: "Test listener",
      ...input,
    },
    { toolCallId, messages: [], abortSignal: ctx.abortSignal },
  )) as {
    success: boolean;
    summary: string;
    data: {
      listener: { jobId: string; nonce: string; port: number };
      listenerReady: boolean;
      callbackUrl: string | null;
    };
  };
  if (!result.success || !result.data.listenerReady) {
    throw new Error(`listener not ready: ${result.summary}`);
  }
  return {
    ctx,
    jobId: result.data.listener.jobId,
    nonce: result.data.listener.nonce,
    port: result.data.listener.port,
  };
}

async function pollListener(ctx: ToolContext, jobId: string) {
  return (await pollCallbackListener(ctx).execute?.(
    { jobId, toolCallDescription: "Test poll" },
    { toolCallId: "tc_poll", messages: [], abortSignal: ctx.abortSignal },
  )) as {
    success: boolean;
    summary: string;
    data: {
      status: string;
      listenerReady: boolean;
      port: number;
      callbackHits: number;
      selfTestHits: number;
      unrelatedHits: number;
      recentHits: Array<{
        method: string;
        path: string;
        ip: string;
        body: string;
        bodyTruncated?: boolean;
      }>;
      nonce: string;
      callbackUrl: string | null;
    };
    artifactPaths: string[];
  };
}

/** Real loopback request; resolves with status+body or rejects on refusal. */
function httpGet(url: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c: string) => {
        body += c;
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "apex-cb-listener-"));
  roots.push(root);
});

afterEach(async () => {
  // Stop every listener the fixtures started, ignoring stop races.
  for (const registry of registries.splice(0)) {
    await registry.stopAll().catch(() => {});
  }
  for (const dir of roots.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("callback helper tool selection", () => {
  it("registers the helper surface: fast-strike available, plan mode and exclusions without", () => {
    for (const name of CALLBACK_TOOLS) {
      expect(ALL_TOOL_NAMES).toContain(name);
      expect(FAST_STRIKE_EXCLUDED_TOOL_NAMES).not.toContain(name);
      expect(PLAN_MODE_TOOL_NAMES).not.toContain(name);
    }
  });

  it("stages a CommonJS listener (require-based) so a type:module workspace cannot break it", () => {
    const script = buildCallbackListenerScript({
      port: 0,
      bindAddress: "0.0.0.0",
      nonce: "c".repeat(32),
    });
    expect(script).toContain("require('node:http')");
    expect(script).not.toMatch(/^\s*import\s/m);
    expect(script).toContain("[apex-callback] hit ");
    expect(script).toContain("__apex_ready__");
    // Config is embedded, not read from env or argv.
    expect(script).toContain('const nonce = "cccc');
  });
});

describe("parseCallbackListenerLog", () => {
  it("parses listening, hit, and bind-failure lines and ignores noise", () => {
    const nonce = "a".repeat(32);
    const evidence = parseCallbackListenerLog(
      [
        `$ node -e eval\(\(x\) 0\) ${nonce}`,
        `[apex-callback] listening bind=0.0.0.0 port=44313 nonce=${nonce}`,
        `[apex-callback] hit {"ts":"2026-10-07T10:00:00Z","method":"GET","path":"/${nonce}/cb","source":"callback","ip":"::ffff:127.0.0.1","body":"x","bodyCapped":false}`,
        `[apex-callback] hit {"ts":"2026-10-07T10:00:01Z","method":"GET","path":"/${nonce}/__apex_ready__","source":"selftest","ip":"::1","body":""}`,
        `[apex-callback] hit {"ts":"2026-10-07T10:00:02Z","method":"HEAD","path":"/other","source":"unrelated","ip":"10.0.0.9","body":""}`,
        "[apex] job stopped",
        "[apex-callback] hit {truncated-junk",
      ].join("\n"),
    );
    expect(evidence.listening).toEqual({
      bind: "0.0.0.0",
      port: 44313,
      nonce,
    });
    expect(evidence.hits.map((h) => h.source)).toEqual([
      "callback",
      "selftest",
      "unrelated",
    ]);
    expect(evidence.hits[0]).toMatchObject({
      method: "GET",
      path: `/${nonce}/cb`,
      ip: "::ffff:127.0.0.1",
    });
    expect(evidence.bindFailed).toBeUndefined();
  });

  it("captures bind failures with their error code", () => {
    const evidence = parseCallbackListenerLog(
      "[apex-callback] bind-failed code=EADDRINUSE listen EADDRINUSAGE: address in use",
    );
    expect(evidence.bindFailed?.code).toBe("EADDRINUSE");
    expect(evidence.bindFailed?.detail).toContain("address in use");
  });

  it("carries bodyCapped so truncated bodies are explicit", () => {
    const evidence = parseCallbackListenerLog(
      '[apex-callback] hit {"ts":"t","method":"POST","path":"/p","source":"callback","ip":"","body":"abc","bodyCapped":true}',
    );
    expect(evidence.hits[0]?.bodyCapped).toBe(true);
  });
});

describe("probeUrlFor", () => {
  it("uses portable loopback hosts and brackets IPv6", () => {
    const nonce = "n".repeat(32);
    expect(probeUrlFor("0.0.0.0", 8080, nonce)).toBe(
      `http://127.0.0.1:8080/${nonce}/__apex_ready__`,
    );
    expect(probeUrlFor("::", 8080, nonce)).toBe(
      `http://[::1]:8080/${nonce}/__apex_ready__`,
    );
    expect(probeUrlFor("::1", 8080, nonce)).toBe(
      `http://[::1]:8080/${nonce}/__apex_ready__`,
    );
    expect(probeUrlFor("fe80::1", 8080, nonce)).toBe(
      `http://[fe80::1]:8080/${nonce}/__apex_ready__`,
    );
    expect(probeUrlFor("cb-host", 8080, nonce)).toBe(
      `http://cb-host:8080/${nonce}/__apex_ready__`,
    );
  });
});

describe("callback listener helper (real local jobs)", () => {
  it("starts ready, separates readiness from evidence, survives intervening commands, and correlates nonce callbacks", async () => {
    const ctx = makeCtx();
    const listener = await startListener(ctx, {
      advertisedBaseUrl: "http://cb.example",
    });

    // The job command is the platform-shell bootstrap form — inline base64
    // payload (quote- and percent-free itself), no path quoting — and it
    // embeds this listener's nonce.
    const jobCommand = (await resolveWhiteboxJobs(ctx).poll(listener.jobId))
      ?.command;
    expect(jobCommand).toMatch(
      /^node -e "eval\(Buffer\.from\('[A-Za-z0-9+/=]+','base64'\)\.toString\('utf8'\)\)"$/,
    );
    expect(jobCommand).not.toContain("%");
    const embedded = Buffer.from(
      jobCommand
        ?.replace(/^node -e "eval\(Buffer\.from\('/, "")
        .replace(/','base64'\)\.toString\('utf8'\)\)"$/, "") ?? "",
      "base64",
    ).toString("utf8");
    expect(embedded).toContain(listener.nonce);
    expect(embedded).toContain("require('node:http')");
    // Script staged as .cjs in the helper workspace.
    expect(ctx.callbackListeners?.get(listener.jobId)?.scriptPath).toMatch(
      /callback-listeners\/listener-[a-f0-9]{32}\.cjs$/,
    );

    // Readiness is confirmed (nonce self-test) but is NOT callback evidence.
    const readyPoll = await pollListener(ctx, listener.jobId);
    expect(readyPoll.success).toBe(true);
    expect(readyPoll.data.listenerReady).toBe(true);
    expect(readyPoll.data.callbackHits).toBe(0);
    expect(readyPoll.data.selfTestHits).toBeGreaterThanOrEqual(1);
    expect(readyPoll.data.callbackUrl).toBe(
      `http://cb.example/${listener.nonce}/cb`,
    );

    // Intervening foreground command through the same command seam.
    const intervening = await collectCommand(
      resolveBackends(ctx).command.run("echo intervening", {
        timeoutSeconds: 10,
      }),
    );
    expect(intervening.exitCode).toBe(0);

    const afterCommand = await pollListener(ctx, listener.jobId);
    expect(afterCommand.data.listenerReady).toBe(true);
    expect(afterCommand.data.status).toBe("running");
    expect(afterCommand.data.callbackHits).toBe(0);

    // Real nonce-correlated callback + unrelated traffic.
    const hit = await httpGet(
      `http://127.0.0.1:${listener.port}/${listener.nonce}/cb?probe=1`,
    );
    expect(hit.status).toBe(200);
    expect(hit.body).toBe(`apex-callback ${listener.nonce}`);
    const foreign = await httpGet(
      `http://127.0.0.1:${listener.port}/someone-elses`,
    );
    expect(foreign.status).toBe(404);
    expect(foreign.body).toBe("not found");

    const evidencePoll = await pollListener(ctx, listener.jobId);
    expect(evidencePoll.data.callbackHits).toBe(1);
    expect(evidencePoll.data.unrelatedHits).toBe(1);
    expect(evidencePoll.data.recentHits[0]).toMatchObject({
      method: "GET",
      path: `/${listener.nonce}/cb?probe=1`,
    });
    expect(evidencePoll.data.recentHits[0]?.bodyTruncated).toBeUndefined();
    // Evidence snapshot persisted once (handle-tracked dedup).
    expect(evidencePoll.artifactPaths).toHaveLength(1);
    const repoll = await pollListener(ctx, listener.jobId);
    expect(repoll.artifactPaths).toEqual(evidencePoll.artifactPaths);

    // Stop: real outcome, evidence preserved, port actually released.
    const stopped = (await stopCallbackListener(ctx).execute?.(
      { jobId: listener.jobId, toolCallDescription: "Test stop" },
      { toolCallId: "tc_stop", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string; artifactPaths: string[] };
    expect(stopped.success).toBe(true);
    expect(stopped.summary).toContain("Final evidence persisted");
    await expect(
      httpGet(`http://127.0.0.1:${listener.port}/${listener.nonce}/cb`),
    ).rejects.toThrow();
    // Late retrieval after the stop: the record and evidence still read.
    const late = await pollListener(ctx, listener.jobId);
    expect(late.data.callbackHits).toBe(1);
    expect(late.data.listenerReady).toBe(false);
    expect(late.data.status).toBe("stopped");
  }, 30_000);

  it("adopts a late listening line's port before probing (start returned pre-listening)", async () => {
    const ctx = makeCtx();
    const listener = await startListener(ctx);
    const handle = ctx.callbackListeners?.get(listener.jobId);
    if (!handle) throw new Error("missing handle");
    // Simulate a start that returned before the listening line was seen:
    // ephemeral port still unknown, readiness unconfirmed.
    handle.port = 0;
    handle.selfTestConfirmed = false;
    handle.lastPersistedSnapshot = undefined;

    const polled = await pollListener(ctx, listener.jobId);
    // The probe that confirmed readiness could only have hit the real
    // port — a probe to port 0 would have left readiness unconfirmed.
    expect(polled.data.listenerReady).toBe(true);
    expect(polled.data.port).toBe(listener.port);
    expect(handle.port).toBe(listener.port);
  }, 30_000);

  it("detects port conflicts promptly without claiming readiness", async () => {
    const ctx = makeCtx();
    const first = await startListener(ctx, { port: 0 });
    const port = first.port;

    const second = (await startCallbackListener(ctx).execute?.(
      {
        port,
        toolCallDescription: "Conflicting listener",
      },
      { toolCallId: "tc_conflict", messages: [], abortSignal: undefined },
    )) as {
      success: boolean;
      summary: string;
      data?: { jobId: string };
    };

    expect(second.success).toBe(false);
    expect(second.summary).toContain("Port conflict");
    expect(second.summary).toContain("EADDRINUSE");
    // The failed listener left no cleanable handle; the first is unaffected.
    const failedJobId = second.data?.jobId;
    expect(failedJobId).toBeDefined();
    expect(ctx.callbackListeners?.get(failedJobId ?? "")).toBeUndefined();
    const firstPoll = await pollListener(ctx, first.jobId);
    expect(firstPoll.data.listenerReady).toBe(true);
    expect(firstPoll.data.status).toBe("running");
  }, 30_000);

  it("keeps cleanup possible after the run abort signal fires", async () => {
    const ctx = makeCtx();
    const listener = await startListener(ctx);

    const ac = new AbortController();
    ac.abort();
    ctx.abortSignal = ac.signal;

    const outcomes = await ctx.callbackListeners?.stopAll();
    expect(outcomes).toEqual([{ jobId: listener.jobId }]);
    await expect(
      httpGet(`http://127.0.0.1:${listener.port}/${listener.nonce}/cb`),
    ).rejects.toThrow();
    expect(ctx.callbackListeners?.get(listener.jobId)).toBeUndefined();
  }, 30_000);

  it("refuses to start when already aborted and registers nothing", async () => {
    const ctx = makeCtx();
    const ac = new AbortController();
    ac.abort();
    ctx.abortSignal = ac.signal;

    const result = (await startCallbackListener(ctx).execute?.(
      { toolCallDescription: "Aborted start" },
      { toolCallId: "tc_aborted", messages: [], abortSignal: ac.signal },
    )) as { success: boolean; summary: string };

    expect(result.success).toBe(false);
    expect(result.summary).toContain("aborted");
    expect(ctx.callbackListeners?.get("tc_aborted")).toBeUndefined();
  }, 30_000);

  it("isolates ownership across sessions and across same-session agents", async () => {
    const ctxA = makeCtx();
    const listener = await startListener(ctxA);

    // Different session, own registry: unknown handle, listener untouched.
    const ctxB = makeCtx({
      session: {
        ...(ctxA.session as SessionInfo),
        id: "ses_other",
      },
    });
    const foreignPoll = (await pollCallbackListener(ctxB).execute?.(
      { jobId: listener.jobId, toolCallDescription: "Foreign poll" },
      { toolCallId: "tc_foreign", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string };
    expect(foreignPoll.success).toBe(false);
    expect(foreignPoll.summary).toContain("not owned by this agent");

    const foreignStop = (await stopCallbackListener(ctxB).execute?.(
      { jobId: listener.jobId, toolCallDescription: "Foreign stop" },
      { toolCallId: "tc_foreign_stop", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string };
    expect(foreignStop.success).toBe(false);

    // Same session id but a different agent's registry: still refused —
    // a job id alone must never authorize stopping another agent's listener.
    const ctxC = makeCtx();
    const sameSessionStop = (await stopCallbackListener(ctxC).execute?.(
      { jobId: listener.jobId, toolCallDescription: "Sibling agent stop" },
      { toolCallId: "tc_sibling", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string };
    expect(sameSessionStop.success).toBe(false);
    expect(sameSessionStop.summary).toContain("not owned by this agent");

    const ownerPoll = await pollListener(ctxA, listener.jobId);
    expect(ownerPoll.data.status).toBe("running");
    expect(ownerPoll.data.listenerReady).toBe(true);
  }, 30_000);

  it("returns the persisted snapshot when the job record is gone (no replay)", async () => {
    const ctx = makeCtx();
    // A handle whose job never exists here, with a planted snapshot.
    const { writeWhiteboxArtifact } = await import("../../../whitebox");
    const ref = await writeWhiteboxArtifact({
      session: ctx.session,
      area: "scratchpad",
      type: "raw-output",
      name: "callback-evidence-wjob_99999_deadbeef",
      description: "planted snapshot",
      content: JSON.stringify({
        jobId: "wjob_99999_deadbeef",
        nonce: "b".repeat(32),
        hits: [
          {
            ts: "t",
            method: "GET",
            path: "/b/cb",
            source: "callback",
            ip: "1.2.3.4",
            body: "",
          },
        ],
        logTruncated: false,
      }),
    });
    const jobId = "wjob_99999_deadbeef";
    ctx.callbackListeners?.register({
      jobId,
      nonce: "b".repeat(32),
      scriptPath: "/tmp/planted.cjs",
      bindAddress: "0.0.0.0",
      port: 1,
      selfTestConfirmed: true,
      artifactPath: ref.path,
      stop: async () => undefined,
    });

    const gone = await pollListener(ctx, jobId);
    expect(gone.success).toBe(true);
    expect(gone.data.status).toBe("record-gone");
    expect(gone.data.callbackHits).toBe(1);
    expect(gone.data.listenerReady).toBe(false);
    expect(gone.summary).toContain("persisted evidence snapshot");

    // No handle at all: explicit unknown, never an implicit replay.
    const unknown = (await pollCallbackListener(ctx).execute?.(
      { jobId: "wjob_99999_cafef00d", toolCallDescription: "Unknown" },
      { toolCallId: "tc_unknown", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string };
    expect(unknown.success).toBe(false);
    expect(unknown.summary).toContain("not owned by this agent");
  });

  it("re-probes an unconfirmed listener instead of promoting a selftest log line", async () => {
    const ctx = makeCtx();
    const listener = await startListener(ctx);

    // Simulate readiness never having been confirmed at start: poll must
    // establish it with a fresh bounded nonce probe, not a log line.
    const handle = ctx.callbackListeners?.get(listener.jobId);
    expect(handle).toBeDefined();
    if (!handle) throw new Error("missing handle");
    handle.selfTestConfirmed = false;

    const repolled = await pollListener(ctx, listener.jobId);
    expect(repolled.data.listenerReady).toBe(true);
    expect(handle.selfTestConfirmed).toBe(true);
    expect(repolled.data.callbackHits).toBe(0);
    // The re-probe's own hit lands as selftest evidence in the next read
    // (poll reads evidence before probing) — never as a callback.
    let settled = await pollListener(ctx, listener.jobId);
    for (let i = 0; i < 20 && settled.data.selfTestHits < 2; i++) {
      await new Promise((r) => setTimeout(r, 100));
      settled = await pollListener(ctx, listener.jobId);
    }
    expect(settled.data.selfTestHits).toBeGreaterThanOrEqual(2);
    expect(settled.data.callbackHits).toBe(0);
    expect(settled.data.listenerReady).toBe(true);
  }, 30_000);

  it("stop surfaces a failed final evidence read without fabricating empty hits", async () => {
    const ctx = makeCtx();
    const jobId = "wjob_88888_cafef00d";
    ctx.callbackListeners?.register({
      jobId,
      nonce: "e".repeat(32),
      scriptPath: "/tmp/none.cjs",
      bindAddress: "0.0.0.0",
      port: 1,
      selfTestConfirmed: true,
      stop: async () => undefined,
    });

    const stopped = (await stopCallbackListener(ctx).execute?.(
      { jobId, toolCallDescription: "No-evidence stop" },
      { toolCallId: "tc_no_evidence", messages: [], abortSignal: undefined },
    )) as {
      success: boolean;
      summary: string;
      data: { callbackHits?: number };
      artifactPaths: string[];
    };

    expect(stopped.success).toBe(true);
    expect(stopped.summary).toContain("could not be re-read");
    expect(stopped.summary).not.toContain("Final evidence persisted");
    expect(stopped.data.callbackHits).toBeUndefined();
    expect(stopped.artifactPaths).toEqual([]);
  });

  it("reports missing Node as unavailable instead of false readiness", async () => {
    const commands: string[] = [];
    const ctx = makeCtx();
    ctx.backends = {
      command: {
        platform: "posix",
        run: (cmd: string) =>
          (async function* () {
            commands.push(cmd);
            yield { type: "start" } as CommandEvent;
            yield {
              type: "stderr",
              seq: 0,
              bytes: "sh: node: command not found",
            } as CommandEvent;
            yield {
              type: "end",
              exitCode: 127,
              timedOut: false,
            } as CommandEvent;
          })(),
      },
    } as unknown as ToolContext["backends"];

    const result = (await startCallbackListener(ctx).execute?.(
      { toolCallDescription: "No node here" },
      { toolCallId: "tc_no_node", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string };

    expect(result.success).toBe(false);
    expect(result.summary).toContain("Node.js is not available");
    expect(result.summary).toContain("127");
    // Only the preflight ran; no job was started.
    expect(commands).toEqual(["node --version"]);
    expect(ctx.callbackListeners?.get("tc_no_node")).toBeUndefined();
  });
});

describe("callback listener helper (remote-adapter contract, local machine)", () => {
  // Local command-adapter fixture: the injected backend routes through the
  // REAL whitebox supervisor bootstrap (serialized kernel, detached
  // supervisor child, state.json under the helper workspace). This
  // establishes adapter contract behavior on this machine — not a live
  // remote deployment.
  it("runs the full supervisor protocol through an injected command backend", async () => {
    const helperRoot = mkdtempSync(join(tmpdir(), "apex-cb-remote-"));
    roots.push(helperRoot);
    const base = makeCtx();
    const ctx = makeCtx({
      session: base.session,
      agentCwd: helperRoot,
      fileWorkspaceRoot: helperRoot,
    });
    ctx.backends = LocalBackends({
      ...ctx,
      backends: undefined,
      sandbox: undefined,
      commandShell: undefined,
      fileWorkspaceRoot: helperRoot,
      agentCwd: helperRoot,
    });

    const listener = await startListener(ctx, {
      advertisedBaseUrl: "http://cb-remote.example",
    });

    // Readiness self-test ran through the same command environment.
    const ready = await pollListener(ctx, listener.jobId);
    expect(ready.data.listenerReady).toBe(true);
    expect(ready.data.selfTestHits).toBeGreaterThanOrEqual(1);
    expect(ready.data.callbackHits).toBe(0);

    const hit = await httpGet(
      `http://127.0.0.1:${listener.port}/${listener.nonce}/cb`,
    );
    expect(hit.status).toBe(200);

    const evidence = await pollListener(ctx, listener.jobId);
    expect(evidence.data.callbackHits).toBe(1);

    const stopped = (await stopCallbackListener(ctx).execute?.(
      { jobId: listener.jobId, toolCallDescription: "Remote-adapter stop" },
      { toolCallId: "tc_remote_stop", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string };
    expect(stopped.success).toBe(true);
    await expect(
      httpGet(`http://127.0.0.1:${listener.port}/${listener.nonce}/cb`),
    ).rejects.toThrow();
  }, 45_000);
});

describe("composeCallbackUrl (path-aware composition)", () => {
  const nonce = "n".repeat(32);

  it("preserves route prefixes and composes the nonce path", () => {
    expect(composeCallbackUrl("http://cb.example", nonce)).toBe(
      `http://cb.example/${nonce}/cb`,
    );
    expect(composeCallbackUrl("http://cb.example/", nonce)).toBe(
      `http://cb.example/${nonce}/cb`,
    );
    expect(composeCallbackUrl("http://cb.example/route", nonce)).toBe(
      `http://cb.example/route/${nonce}/cb`,
    );
    expect(composeCallbackUrl("http://cb.example/route/", nonce)).toBe(
      `http://cb.example/route/${nonce}/cb`,
    );
    expect(composeCallbackUrl("http://cb.example:8081", nonce)).toBe(
      `http://cb.example:8081/${nonce}/cb`,
    );
    expect(composeCallbackUrl("http://[::1]:8081/base", nonce)).toBe(
      `http://[::1]:8081/base/${nonce}/cb`,
    );
    expect(composeCallbackUrl("https://cb.example", nonce)).toBe(
      `https://cb.example/${nonce}/cb`,
    );
  });

  it("keeps query parameters after the nonce path and strips fragments", () => {
    expect(composeCallbackUrl("http://cb.example/route?token=abc", nonce)).toBe(
      `http://cb.example/route/${nonce}/cb?token=abc`,
    );
    expect(
      composeCallbackUrl("http://cb.example/route/?token=abc&x=1", nonce),
    ).toBe(`http://cb.example/route/${nonce}/cb?token=abc&x=1`);
    expect(composeCallbackUrl("http://cb.example#frag", nonce)).toBe(
      `http://cb.example/${nonce}/cb`,
    );
    expect(
      composeCallbackUrl("http://cb.example/route?token=abc#frag", nonce),
    ).toBe(`http://cb.example/route/${nonce}/cb?token=abc`);
  });

  it("returns undefined for an unparseable base instead of a broken URL", () => {
    expect(composeCallbackUrl("not a url", nonce)).toBeUndefined();
    expect(composeCallbackUrl("", nonce)).toBeUndefined();
  });
});

describe("record-gone snapshot retrieval (bugbot regressions)", () => {
  const GONE_NONCE = "9".repeat(32);

  async function plantSnapshot(
    ctx: ToolContext,
    jobId: string,
    content: string,
  ) {
    return writeWhiteboxArtifact({
      session: ctx.session,
      area: "scratchpad",
      type: "raw-output",
      name: `callback-evidence-${jobId}`,
      description: "planted snapshot",
      content,
    });
  }

  function registerGone(ctx: ToolContext, jobId: string, artifactPath: string) {
    ctx.callbackListeners?.register({
      jobId,
      nonce: GONE_NONCE,
      scriptPath: "/tmp/gone.cjs",
      bindAddress: "0.0.0.0",
      port: 3,
      selfTestConfirmed: true,
      artifactPath,
      stop: async () => undefined,
    });
  }

  function snapshotHits(count: number, bodyChars: number) {
    return Array.from({ length: count }, (_, i) => ({
      ts: `2026-10-07T10:00:${String(i % 60).padStart(2, "0")}Z`,
      method: "GET",
      path: `/${GONE_NONCE}/cb?i=${i}`,
      source: "callback" as const,
      ip: "10.0.0.1",
      body: "x".repeat(bodyChars),
    }));
  }

  it("retrieves a retained snapshot larger than the 40k inline cap", async () => {
    const ctx = makeCtx();
    const jobId = "wjob_66666_a001";
    const hits = snapshotHits(130, 120);
    // The actual compact log lines (prefix included) fit the 40k log
    // window; the pretty-printed snapshot exceeds the 40k inline cap —
    // the real amplification the inline-capped read used to lose.
    const compact = hits
      .map((h) => `[apex-callback] hit ${JSON.stringify(h)}`)
      .join("\n");
    expect(Buffer.byteLength(compact)).toBeLessThanOrEqual(40_000);
    const content = JSON.stringify(
      { jobId, nonce: GONE_NONCE, hits, logTruncated: false },
      null,
      2,
    );
    expect(content.length).toBeGreaterThan(40_000);
    const ref = await plantSnapshot(ctx, jobId, content);
    registerGone(ctx, jobId, ref.path);

    const poll = await pollListener(ctx, jobId);
    expect(poll.success).toBe(true);
    expect(poll.data.status).toBe("record-gone");
    expect(poll.data.callbackHits).toBe(130);
    expect(poll.artifactPaths).toEqual([ref.path]);
  });

  it("reports a corrupt retained snapshot as unreadable, never as absent", async () => {
    const ctx = makeCtx();
    const jobId = "wjob_66666_b002";
    const ref = await plantSnapshot(
      ctx,
      jobId,
      '{"jobId": "broken", "hits": [ {truncated',
    );
    registerGone(ctx, jobId, ref.path);

    const poll = (await pollCallbackListener(ctx).execute?.(
      { jobId, toolCallDescription: "Corrupt snapshot poll" },
      { toolCallId: "tc_corrupt", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string; artifactPaths: string[] };
    expect(poll.success).toBe(false);
    expect(poll.summary).toContain("could not be read");
    expect(poll.summary).toContain("corrupt");
    // Truthful distinction: the snapshot exists — never reported absent.
    expect(poll.summary).not.toContain("no persisted evidence snapshot");
    expect(poll.artifactPaths).toEqual([ref.path]);
  });

  it("rejects valid-JSON snapshots with a malformed hits shape, never zero-hit success", async () => {
    const ctx = makeCtx();
    const wrongType = "wjob_66666_d004";
    const refType = await plantSnapshot(
      ctx,
      wrongType,
      JSON.stringify({ jobId: wrongType, nonce: GONE_NONCE, hits: "bad" }),
    );
    registerGone(ctx, wrongType, refType.path);
    const wrongEntry = "wjob_66666_e005";
    const refEntry = await plantSnapshot(
      ctx,
      wrongEntry,
      JSON.stringify({
        jobId: wrongEntry,
        nonce: GONE_NONCE,
        hits: [
          {
            ts: "t",
            method: "GET",
            path: "/x",
            source: "callback",
            ip: "",
            body: "",
          },
          { ts: 42 },
        ],
      }),
    );
    registerGone(ctx, wrongEntry, refEntry.path);

    for (const [jobId, ref] of [
      [wrongType, refType],
      [wrongEntry, refEntry],
    ] as const) {
      const poll = (await pollCallbackListener(ctx).execute?.(
        { jobId, toolCallDescription: "Malformed snapshot poll" },
        { toolCallId: `tc_${jobId}`, messages: [], abortSignal: undefined },
      )) as { success: boolean; summary: string; artifactPaths: string[] };
      expect(poll.success).toBe(false);
      expect(poll.summary).toContain("could not be read");
      expect(poll.summary).toContain("corrupt");
      expect(poll.summary).not.toContain("no persisted evidence snapshot");
      expect(poll.artifactPaths).toEqual([ref.path]);
    }
  });

  it("reports a snapshot beyond the bounded read cap as capped, preserving it", async () => {
    const ctx = makeCtx();
    const jobId = "wjob_66666_c003";
    const content = JSON.stringify(
      { jobId, nonce: GONE_NONCE, hits: snapshotHits(6000, 200) },
      null,
      2,
    );
    expect(content.length).toBeGreaterThan(1_000_000);
    const ref = await plantSnapshot(ctx, jobId, content);
    registerGone(ctx, jobId, ref.path);

    const poll = (await pollCallbackListener(ctx).execute?.(
      { jobId, toolCallDescription: "Capped snapshot poll" },
      { toolCallId: "tc_capped", messages: [], abortSignal: undefined },
    )) as { success: boolean; summary: string; artifactPaths: string[] };
    expect(poll.success).toBe(false);
    expect(poll.summary).toContain("bounded read cap");
    expect(poll.summary).not.toContain("no persisted evidence snapshot");
    expect(poll.artifactPaths).toEqual([ref.path]);
  });

  it("composes the callback URL path-aware for tokenized route bases", async () => {
    const ctx = makeCtx();
    const listener = await startListener(ctx, {
      advertisedBaseUrl: "http://cb.example/route?token=abc",
    });

    const poll = await pollListener(ctx, listener.jobId);
    expect(poll.data.callbackUrl).toBe(
      `http://cb.example/route/${listener.nonce}/cb?token=abc`,
    );
  }, 30_000);
});

describe("CallbackListenerRegistry cleanup retry", () => {
  it("keeps a failed stop registered, then cleans it on retry", async () => {
    const registry = new CallbackListenerRegistry();
    let attempts = 0;
    const handle = {
      jobId: "wjob_77777_retry0",
      nonce: "f".repeat(32),
      scriptPath: "/tmp/retry.cjs",
      bindAddress: "0.0.0.0",
      port: 2,
      selfTestConfirmed: false,
      stop: async () => {
        attempts += 1;
        if (attempts === 1) throw new Error("first stop fails");
        return undefined;
      },
    };
    registry.register(handle);

    // First drain (abortAndDrain path): the stop throws; the handle must
    // stay registered so finalizeRun can retry this owner.
    const first = await registry.stopAll();
    expect(first).toEqual([
      { jobId: "wjob_77777_retry0", error: "first stop fails" },
    ]);
    expect(registry.get("wjob_77777_retry0")).toBe(handle);

    // Second drain (finalizeRun path): the retry succeeds and cleans up.
    const second = await registry.stopAll();
    expect(second).toEqual([{ jobId: "wjob_77777_retry0" }]);
    expect(registry.get("wjob_77777_retry0")).toBeUndefined();
  });
});

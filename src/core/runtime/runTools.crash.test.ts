/**
 * Component crash acceptance for the tool journal: real SQLite, real
 * subprocess SIGKILL, real loopback HTTP target. Not public resume —
 * only that committed journal rows survive and drive reuse/refusal.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolSet } from "ai";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { wrapRecordedTools } from "../agents/offSecAgent/recordedTools";
import { createRunToolRecorder } from "./runTools";
import { openSqliteRunStore } from "./sqliteRunStore";

type Store = Awaited<ReturnType<typeof openSqliteRunStore>>;

const RUN_ID = "run_tool_crash";
const TOOL_CALL_ID = "tc_http_1";

let tempDirs: string[] = [];
let children: ChildProcess[] = [];
let target: Server | undefined;
// The server is the only counter — every POST increments it exactly once.
let targetHits = 0;
let targetPort = 0;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function tempDb(): string {
  return join(tempDir("runtools-db-"), "runs.sqlite");
}

function specFixture(cwd: string) {
  return {
    schemaVersion: 1,
    configVersion: 1,
    runId: RUN_ID,
    prompt: "Request the target once and summarize the response.",
    target: `http://127.0.0.1:${targetPort}`,
    model: "claude-sonnet-5-5",
    activeTools: ["http_request"],
    environment: { kind: "local", cwd },
    scope: {
      version: 1,
      allowedHosts: ["127.0.0.1"],
      allowedPorts: [targetPort],
      strictScope: true,
      allowDestructiveActions: false,
      allowRateLimitTesting: false,
    },
    credentialRefs: [],
  };
}

async function withStore<T>(
  dbPath: string,
  fn: (store: Store) => Promise<T>,
): Promise<T> {
  const store = await openSqliteRunStore(dbPath);
  try {
    return await fn(store);
  } finally {
    store.close();
  }
}

/** Parent-side duplicate probe: a plain http_request the wrapper gates. */
function probeHttpTool(): ToolSet {
  return {
    http_request: {
      execute: async () => {
        const res = await fetch(`http://127.0.0.1:${targetPort}/probe`, {
          method: "POST",
        });
        return { status: res.status, from: "probe" };
      },
    },
  } as unknown as ToolSet;
}

function wrappedProbe(store: Store, attemptId: string): ToolSet {
  const rec = createRunToolRecorder({
    runId: RUN_ID,
    executionAttemptId: attemptId,
    store,
    collectEvidence: async () => ({
      rootPath: tempDir("runtools-session-"),
      files: [],
    }),
  });
  return wrapRecordedTools(probeHttpTool(), rec);
}

/** Invoke a wrapped tool's execute without fighting optional-typing. */
function invoke(
  tools: ToolSet,
  name: string,
  input: unknown,
  toolCallId: string,
): Promise<unknown> {
  const tool = tools[name] as {
    execute?: (i: never, o: never) => Promise<unknown> | unknown;
  };
  if (typeof tool?.execute !== "function") {
    throw new Error(`tool is not executable: ${name}`);
  }
  return Promise.resolve(tool.execute(input as never, { toolCallId } as never));
}

/**
 * Child source. Mid-flight: the tool fetches (target mutates), signals,
 * then stalls INSIDE execute — the wrapper never reaches settle.
 * Settled: the tool returns, the wrapper settles, then the child idles.
 */
function childSource(mode: "crash-mid-flight" | "settle-then-crash"): {
  source: string;
  sessionRoot: string;
} {
  const storeSource = join(import.meta.dirname, "sqliteRunStore.ts");
  const runToolsSource = join(import.meta.dirname, "runTools.ts");
  const recordedToolsSource = join(
    import.meta.dirname,
    "../agents/offSecAgent/recordedTools.ts",
  );
  const cwd = tempDir("runtools-child-cwd-");
  const sessionRoot = tempDir("runtools-child-session-");
  const source = `
import { openSqliteRunStore } from ${JSON.stringify(storeSource)};
import { createRunToolRecorder } from ${JSON.stringify(runToolsSource)};
import { wrapRecordedTools } from ${JSON.stringify(recordedToolsSource)};

const [dbPath, mode, portText] = process.argv.slice(2);
const port = Number(portText);
const runId = ${JSON.stringify(RUN_ID)};

const store = await openSqliteRunStore(dbPath);
const admitted = await store.admit({
  schemaVersion: 1,
  configVersion: 1,
  runId,
  prompt: "Request the target once and summarize the response.",
  target: \`http://127.0.0.1:\${port}\`,
  model: "claude-sonnet-5-5",
  activeTools: ["http_request"],
  environment: { kind: "local", cwd: ${JSON.stringify(cwd)} },
  scope: {
    version: 1,
    allowedHosts: ["127.0.0.1"],
    allowedPorts: [port],
    strictScope: true,
    allowDestructiveActions: false,
    allowRateLimitTesting: false,
  },
  credentialRefs: [],
});
const attemptId = admitted.record.attemptId;
await store.transition(runId, attemptId, "running");
await store.initializeToolJournal(runId, attemptId);
await store.commitContext(runId, attemptId, 0, {
  kind: "replace",
  messages: [{ role: "user", content: "fetch the target" }],
  system: "system prompt",
});

const recorder = createRunToolRecorder({
  runId,
  executionAttemptId: attemptId,
  store,
  collectEvidence: async () => ({
    rootPath: ${JSON.stringify(sessionRoot)},
    files: [],
  }),
});
const tools = wrapRecordedTools({
  http_request: {
    inputSchema: {},
    execute: async (input) => {
      const res = await fetch(\`http://127.0.0.1:\${port}/child\`, {
        method: "POST",
        body: JSON.stringify(input),
      });
      if (mode === "crash-mid-flight") {
        // Target already mutated; stall before the wrapper can settle.
        console.log("IN_FLIGHT");
        await new Promise(() => {});
      }
      return { status: res.status, from: "child" };
    },
  },
}, recorder);

setInterval(() => {}, 1000);
const gate = await tools.http_request.execute(
  { url: \`http://127.0.0.1:\${port}/child\`, method: "POST" },
  { toolCallId: ${JSON.stringify(TOOL_CALL_ID)} },
);
console.log("SETTLED:" + JSON.stringify(gate));
`;
  return { source, sessionRoot };
}

/**
 * Observe the child marker or fail on exit; bound the wait on every path.
 */
function waitForMarker(child: ChildProcess, marker: RegExp): Promise<string> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      fn();
    };
    child.stdout!.on("data", (c) => {
      stdout += c;
      const m = stdout.match(marker);
      if (m) finish(() => resolve(m[0]));
    });
    child.stderr!.on("data", (c) => (stderr += c));
    // A child that dies before signaling must fail the wait, not hang it.
    child.on("close", () =>
      finish(() =>
        reject(
          new Error(
            `child exited before marker.\nstdout=${stdout}\nstderr=${stderr}`,
          ),
        ),
      ),
    );
    child.on("error", (e) => finish(() => reject(e)));
    timer = setTimeout(
      () =>
        finish(() =>
          reject(
            new Error(
              `child produced no marker.\nstdout=${stdout}\nstderr=${stderr}`,
            ),
          ),
        ),
      30000,
    );
  });
}

async function killAndAwait(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("Child did not exit after SIGKILL")),
      5000,
    );
    child.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGKILL");
  });
}

beforeAll(async () => {
  tempDirs = [];
  children = [];
  targetHits = 0;
  target = createServer((req, res) => {
    if (req.method === "POST") {
      targetHits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(204);
    res.end();
  });
  await new Promise<void>((resolve) => target!.listen(0, "127.0.0.1", resolve));
  targetPort = (target!.address() as { port: number }).port;
});

afterAll(async () => {
  for (const child of children) await killAndAwait(child);
  if (target) {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 5000);
      target!.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("tool journal under subprocess SIGKILL", () => {
  it("mid-flight crash: started with no output, duplicate refused, target untouched", async () => {
    const dbPath = tempDb();
    const { source } = childSource("crash-mid-flight");
    const fixtureDir = tempDir("runtools-fixture-");
    const script = join(fixtureDir, "child.ts");
    writeFileSync(script, source);
    const child = spawn(
      "bun",
      [script, dbPath, "crash-mid-flight", String(targetPort)],
      {
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    children.push(child);

    expect(await waitForMarker(child, /^IN_FLIGHT$/m)).toBe("IN_FLIGHT");
    const hitsAfterChild = targetHits;

    await killAndAwait(child);
    expect(child.signalCode).toBe("SIGKILL");

    await withStore(dbPath, async (store) => {
      expect((await store.get(RUN_ID))?.status).toBe("running");
      const ops = await store.listToolOperations(RUN_ID);
      expect(ops).toHaveLength(1);
      expect(ops[0]).toMatchObject({
        toolCallId: TOOL_CALL_ID,
        toolName: "http_request",
        policy: "external_effect",
        state: "started",
      });
      expect(ops[0].output).toBeUndefined();

      // A fresh recorder over the surviving journal refuses the duplicate.
      const attemptId = (await store.get(RUN_ID))!.attemptId;
      const tools = wrappedProbe(store, attemptId);
      await expect(
        invoke(
          tools,
          "http_request",
          {
            url: `http://127.0.0.1:${targetPort}/child`,
            method: "POST",
          },
          TOOL_CALL_ID,
        ),
      ).rejects.toThrow();
      // Refusal happened before the wrapped execute body ran: no probe
      // reached the server.
      expect(targetHits).toBe(hitsAfterChild);
    });
  });

  it("settled-then-crash: exact output and evidence survive; duplicate reuses without HTTP", async () => {
    const dbPath = tempDb();
    const { source, sessionRoot } = childSource("settle-then-crash");
    const fixtureDir = tempDir("runtools-fixture-");
    const script = join(fixtureDir, "child.ts");
    writeFileSync(script, source);
    const child = spawn(
      "bun",
      [script, dbPath, "settle-then-crash", String(targetPort)],
      {
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    children.push(child);

    const settledLine = await waitForMarker(child, /^SETTLED:.*$/m);
    const childResult = JSON.parse(settledLine.slice("SETTLED:".length));
    const hitsAfterChild = targetHits;

    await killAndAwait(child);
    expect(child.signalCode).toBe("SIGKILL");

    await withStore(dbPath, async (store) => {
      const ops = await store.listToolOperations(RUN_ID);
      expect(ops).toHaveLength(1);
      expect(ops[0]).toMatchObject({
        toolCallId: TOOL_CALL_ID,
        toolName: "http_request",
        state: "settled",
      });
      // The exact settled output and the evidence captured at settle time.
      expect(ops[0].output).toEqual({
        type: "json",
        value: { status: 200, from: "child" },
      });
      expect(ops[0].evidence).toEqual({ rootPath: sessionRoot, files: [] });
      // The pre-crash context snapshot survives alongside the operation.
      const context = await store.getContext(RUN_ID);
      expect(context?.epoch).toBe(1);
      expect(context?.messages).toEqual([
        { role: "user", content: "fetch the target" },
      ]);

      // The duplicate wrapper reuses the stored output — no HTTP request.
      const attemptId = (await store.get(RUN_ID))!.attemptId;
      const tools = wrappedProbe(store, attemptId);
      const reused = await invoke(
        tools,
        "http_request",
        {
          url: `http://127.0.0.1:${targetPort}/child`,
          method: "POST",
        },
        TOOL_CALL_ID,
      );
      expect(reused).toEqual(childResult);
      expect(targetHits).toBe(hitsAfterChild);
    });
  });
});

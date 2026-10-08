import { afterEach, describe, expect, it } from "vitest";
import type {
  CommandBackend,
  CommandEvent,
  RunOpts,
  ToolBackends,
} from "../../tools/backends/types";
import {
  buildBundledAssetsSection,
  buildRuntimeContextSection,
  MAX_CACHE_ENTRIES,
  PROBE_TOOL_NAMES,
  peekSettledRuntimeFacts,
  probeRuntimeFacts,
  type RuntimeExecutionFacts,
  resetRuntimeFactsCache,
  resolveCommandPlatform,
  UNKNOWN_FACTS,
} from "./runtimeContext";
import { PerCommandShell } from "./tools/perCommandShell";
import type { ToolContext } from "./tools/types";

afterEach(() => {
  resetRuntimeFactsCache();
});

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type RecordedCall = { cmd: string; opts: RunOpts | undefined };

function fakeBackends(
  respond: (cmd: string) => CommandEvent[],
  platform: "posix" | "windows" = "posix",
): { backend: ToolBackends; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const command: CommandBackend = {
    platform,
    run: (cmd: string, o?: RunOpts) => {
      calls.push({ cmd, opts: o });
      const events = respond(cmd);
      return (async function* () {
        for (const event of events) yield event;
      })();
    },
  };
  return { backend: { command } as unknown as ToolBackends, calls };
}

function markerOutput(
  available: readonly string[],
  missing: readonly string[] = [],
  os = "Linux 6.5.0-test",
): string {
  return [
    ...available.map((t) => `AVAIL ${t}`),
    ...missing.map((t) => `MISSING ${t}`),
    `OS: ${os}`,
  ].join("\n");
}

function successEvents(output: string): CommandEvent[] {
  return [
    { type: "stdout", seq: 0, bytes: output },
    { type: "end", exitCode: 0, timedOut: false },
  ];
}

function fullInventoryBackend(available: readonly string[]): {
  backend: ToolBackends;
  calls: RecordedCall[];
} {
  const missing = PROBE_TOOL_NAMES.filter((t) => !available.includes(t));
  return fakeBackends(() => successEvents(markerOutput(available, missing)));
}

let ctxCounter = 0;

function makeCtx(overrides: {
  backends?: ToolBackends;
  sandbox?: unknown;
  session?: string;
  agentCwd?: string;
  environmentVariables?: Record<string, string>;
}): ToolContext {
  return {
    session: { id: overrides.session ?? `ses-ctx-${++ctxCounter}` },
    agentCwd: overrides.agentCwd ?? "/workspace",
    backends: overrides.backends,
    sandbox: overrides.sandbox,
    environmentVariables: overrides.environmentVariables,
  } as unknown as ToolContext;
}

// ---------------------------------------------------------------------------
// probeRuntimeFacts
// ---------------------------------------------------------------------------

describe("probeRuntimeFacts", () => {
  it("parses a complete backend inventory", async () => {
    const available = ["bash", "curl", "ffuf", "git", "node", "python3", "sh"];
    const { backend, calls } = fullInventoryBackend(available);
    const facts = await probeRuntimeFacts(makeCtx({ backends: backend }));
    expect(facts.probed).toBe(true);
    expect(facts.available).toEqual([...available].sort());
    expect(facts.missing).toEqual(
      PROBE_TOOL_NAMES.filter((t) => !available.includes(t)).sort(),
    );
    expect(facts.os).toBe("Linux 6.5.0-test");
    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toContain("command -v ffuf");
  });

  it("missing interpreters cannot fail the probe (no failing version tail)", async () => {
    const available = PROBE_TOOL_NAMES.filter(
      (t) => t !== "node" && t !== "python",
    );
    const { backend, calls } = fullInventoryBackend(available);
    const facts = await probeRuntimeFacts(makeCtx({ backends: backend }));
    // The command must end with the always-succeeding OS echo — a missing
    // node/python must not turn the whole inventory unknown via exit 127.
    expect(calls[0].cmd).toMatch(/echo "OS: \$\(uname -sr 2>\/dev\/null\)"$/);
    expect(facts.probed).toBe(true);
    expect(facts.missing).toEqual(["node", "python"]);
  });

  it("nonzero exit, timeout, and backend truncation all mean unknown, never absent", async () => {
    const cases: CommandEvent[][] = [
      [{ type: "end", exitCode: 127, timedOut: false }],
      [{ type: "end", exitCode: 0, timedOut: true }],
      [
        { type: "stdout", seq: 0, bytes: markerOutput(PROBE_TOOL_NAMES) },
        { type: "end", exitCode: 0, timedOut: false, stdoutTruncated: true },
      ],
    ];
    for (const events of cases) {
      const { backend } = fakeBackends(() => events);
      const facts = await probeRuntimeFacts(makeCtx({ backends: backend }));
      expect(facts).toEqual(UNKNOWN_FACTS);
    }
  });

  it("output past the capture cap invalidates the probe", async () => {
    const { backend } = fakeBackends(() => [
      { type: "stdout", seq: 0, bytes: "x".repeat(64 * 1024) },
      { type: "end", exitCode: 0, timedOut: false },
    ]);
    expect(await probeRuntimeFacts(makeCtx({ backends: backend }))).toEqual(
      UNKNOWN_FACTS,
    );
  });

  it("a partial marker set reads as unknown, not everything-absent", async () => {
    const { backend } = fakeBackends(() =>
      successEvents(["AVAIL bash", "OS: Linux 6.5.0"].join("\n")),
    );
    expect(await probeRuntimeFacts(makeCtx({ backends: backend }))).toEqual(
      UNKNOWN_FACTS,
    );
  });

  it("passes the configured execution env with the probe command", async () => {
    const { backend, calls } = fullInventoryBackend(["bash", "sh"]);
    await probeRuntimeFacts(
      makeCtx({
        backends: backend,
        environmentVariables: { PATH: "/opt/bin", SECRET_TOKEN: "s3cr3t" },
      }),
    );
    expect(calls[0].opts?.envVars).toEqual({
      PATH: "/opt/bin",
      SECRET_TOKEN: "s3cr3t",
    });
  });

  it("coalesces concurrent and repeat probes within one runtime scope", async () => {
    const { backend, calls } = fullInventoryBackend(["bash", "sh"]);
    const ctx = makeCtx({ backends: backend });
    const [a, b] = await Promise.all([
      probeRuntimeFacts(ctx),
      probeRuntimeFacts(ctx),
    ]);
    expect(a).toEqual(b);
    expect(await probeRuntimeFacts(ctx)).toEqual(a);
    expect(calls).toHaveLength(1);
  });

  it("cancels only the caller's wait while a sibling completes the shared probe", async () => {
    const owner = new AbortController();
    const sibling = new AbortController();
    let release!: () => void;
    let calls = 0;
    const backend = {
      command: {
        run: (_cmd: string, opts?: RunOpts) => {
          calls++;
          const gate = new Promise<boolean>((resolve) => {
            release = () => resolve(true);
            opts?.abortSignal?.addEventListener("abort", () => resolve(false), {
              once: true,
            });
          });
          return (async function* () {
            if (await gate) {
              yield* successEvents(markerOutput(PROBE_TOOL_NAMES));
            } else {
              yield { type: "end" as const, exitCode: 130, timedOut: false };
            }
          })();
        },
      },
    } as unknown as ToolBackends;
    const ctx = makeCtx({ backends: backend });
    const ownerWait = probeRuntimeFacts({ ...ctx, abortSignal: owner.signal });
    const siblingWait = probeRuntimeFacts({
      ...ctx,
      abortSignal: sibling.signal,
    });

    owner.abort();
    expect(await ownerWait).toEqual(UNKNOWN_FACTS);
    expect(peekSettledRuntimeFacts(ctx)).toBeNull();
    release();

    const facts = await siblingWait;
    expect(facts.probed).toBe(true);
    expect(facts.available).toEqual([...PROBE_TOOL_NAMES].sort());
    expect(peekSettledRuntimeFacts(ctx)).toEqual(facts);
    expect(await probeRuntimeFacts(ctx)).toEqual(facts);
    expect(calls).toBe(1);
  });

  it("does not start discovery for an already cancelled caller", async () => {
    const { backend, calls } = fullInventoryBackend(["bash", "sh"]);
    const ctx = makeCtx({ backends: backend });
    const controller = new AbortController();
    controller.abort();
    expect(
      await probeRuntimeFacts({ ...ctx, abortSignal: controller.signal }),
    ).toEqual(UNKNOWN_FACTS);
    expect(calls).toHaveLength(0);
    expect(peekSettledRuntimeFacts(ctx)).toBeNull();
    expect((await probeRuntimeFacts(ctx)).probed).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("uses its own local command lifetime instead of an agent's disposed shell", async () => {
    const shell = new PerCommandShell({ cwd: process.cwd() });
    await shell.dispose();
    const ctx = makeCtx({ agentCwd: process.cwd() });
    const facts = await probeRuntimeFacts({ ...ctx, commandShell: shell });
    expect(facts.probed).toBe(true);
    expect(facts.available.length + facts.missing.length).toBe(
      PROBE_TOOL_NAMES.length,
    );
  });

  it("separates sessions, executor objects, and cwds", async () => {
    const { backend, calls } = fullInventoryBackend(["bash", "sh"]);
    const sandboxA: Record<string, never> = {};
    const sandboxB: Record<string, never> = {};
    await probeRuntimeFacts(
      makeCtx({ backends: backend, session: "ses-1", sandbox: sandboxA }),
    );
    await probeRuntimeFacts(
      makeCtx({ backends: backend, session: "ses-2", sandbox: sandboxA }),
    );
    await probeRuntimeFacts(
      makeCtx({ backends: backend, session: "ses-1", sandbox: sandboxB }),
    );
    await probeRuntimeFacts(
      makeCtx({
        backends: backend,
        session: "ses-1",
        sandbox: sandboxA,
        agentCwd: "/other",
      }),
    );
    expect(calls).toHaveLength(4);
  });

  it("structurally identical env shares a probe; changed env re-probes", async () => {
    const { backend, calls } = fullInventoryBackend(["bash", "sh"]);
    const session = "ses-env";
    await probeRuntimeFacts(
      makeCtx({
        backends: backend,
        session,
        environmentVariables: { A: "1", B: "2" },
      }),
    );
    // Same content, different object identity: same runtime inputs.
    await probeRuntimeFacts(
      makeCtx({
        backends: backend,
        session,
        environmentVariables: { B: "2", A: "1" },
      }),
    );
    expect(calls).toHaveLength(1);
    await probeRuntimeFacts(
      makeCtx({
        backends: backend,
        session,
        environmentVariables: { A: "1", B: "3" },
      }),
    );
    expect(calls).toHaveLength(2);
  });

  it("does not retain failed probes — the next agent retries", async () => {
    let fail = true;
    const { backend, calls } = fakeBackends(() =>
      fail
        ? [{ type: "end", exitCode: 1, timedOut: false }]
        : successEvents(markerOutput(PROBE_TOOL_NAMES)),
    );
    const ctx = makeCtx({ backends: backend });
    expect((await probeRuntimeFacts(ctx)).probed).toBe(false);
    fail = false;
    expect((await probeRuntimeFacts(ctx)).probed).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it("late settlement after eviction cannot repopulate or delete newer entries", async () => {
    // Per-probe gates: each run() stays pending until its own release.
    const gates: Array<{
      release: () => void;
      respond: () => CommandEvent[];
    }> = [];
    const calls: RecordedCall[] = [];
    const backend = {
      command: {
        platform: "posix" as const,
        run: (cmd: string, opts?: RunOpts) => {
          calls.push({ cmd, opts });
          let release!: () => void;
          const gate = new Promise<void>((resolve) => {
            release = resolve;
          });
          const entry = {
            release,
            respond: () => successEvents(markerOutput(PROBE_TOOL_NAMES)),
          };
          gates.push(entry);
          return (async function* () {
            await gate;
            for (const event of entry.respond()) yield event;
          })();
        },
      },
    } as unknown as ToolBackends;
    const ctx = (session: string) =>
      makeCtx({ backends: backend, session }) as ToolContext;

    // An old probe on key K that will settle as a failure…
    const oldFail = probeRuntimeFacts(ctx("ses-race"));
    gates[0].respond = () => [{ type: "end", exitCode: 1, timedOut: false }];
    // …and a success probe on another key, both still pending.
    const orphan = probeRuntimeFacts(ctx("ses-orphan"));

    // Fill past the eviction threshold: both pending scopes are evicted.
    for (let i = 0; i < MAX_CACHE_ENTRIES; i++) {
      void probeRuntimeFacts(ctx(`ses-fill-${i}`));
    }

    // A newer probe takes over key K after the eviction.
    const newer = probeRuntimeFacts(ctx("ses-race"));
    expect(newer).not.toBe(oldFail);

    // The old failure settling must not delete the newer cached promise.
    gates[0].release();
    expect((await oldFail).probed).toBe(false);
    const callsAfterOldFail = calls.length;
    const again = probeRuntimeFacts(ctx("ses-race"));
    expect(again).toBe(newer);
    expect(calls).toHaveLength(callsAfterOldFail);
    expect(peekSettledRuntimeFacts(ctx("ses-race"))).toBeNull();

    // The orphaned success returns to its caller but must not repopulate
    // the evicted scope's settled snapshot.
    gates[1].release();
    expect((await orphan).probed).toBe(true);
    expect(peekSettledRuntimeFacts(ctx("ses-orphan"))).toBeNull();

    // The current promise settles normally into the snapshot.
    gates.at(-1)?.release();
    await newer;
    expect(peekSettledRuntimeFacts(ctx("ses-race"))?.probed).toBe(true);
  });

  it("windows backends get a where-based probe and platform", async () => {
    const { backend, calls } = fakeBackends(
      () =>
        successEvents(
          markerOutput(
            ["bash", "node"],
            PROBE_TOOL_NAMES.filter((t) => !["bash", "node"].includes(t)),
          ),
        ),
      "windows",
    );
    const facts = await probeRuntimeFacts(makeCtx({ backends: backend }));
    expect(calls[0].cmd).toContain("where ffuf");
    expect(calls[0].cmd).not.toContain("command -v");
    expect(facts.probed).toBe(true);
    expect(facts.available).toEqual(["bash", "node"]);
    expect(resolveCommandPlatform(makeCtx({ backends: backend }))).toBe(
      "windows",
    );
  });

  it("windows probe reports the OS from ver output through the backend", async () => {
    // cmd-shaped output: CRLF line endings, bare OS: marker, ver's line.
    const output = [
      ...["bash", "node"].map((t) => `AVAIL ${t}`),
      ...PROBE_TOOL_NAMES.filter((t) => !["bash", "node"].includes(t)).map(
        (t) => `MISSING ${t}`,
      ),
      "OS:",
      "Microsoft Windows [Version 10.0.22621.3152]",
    ].join("\r\n");
    const { backend, calls } = fakeBackends(
      () => successEvents(output),
      "windows",
    );
    const facts = await probeRuntimeFacts(makeCtx({ backends: backend }));
    expect(calls[0].cmd).toContain("echo OS: & ver");
    // Native cmd built-in only — no powershell, no new interpreter, no host
    // uname fallback.
    expect(calls[0].cmd).not.toContain("powershell");
    expect(calls[0].cmd).not.toContain("uname");
    expect(facts.probed).toBe(true);
    expect(facts.os).toBe("Microsoft Windows [Version 10.0.22621.3152]");
  });

  it("a missing ver line degrades the OS to unknown without failing the windows probe", async () => {
    // Every tool absent AND ver produced nothing after the bare marker:
    // exit stays 0 and the inventory is still trustworthy — only the OS
    // reads as unknown.
    const output = [...PROBE_TOOL_NAMES.map((t) => `MISSING ${t}`), "OS:"].join(
      "\r\n",
    );
    const { backend } = fakeBackends(() => successEvents(output), "windows");
    const facts = await probeRuntimeFacts(makeCtx({ backends: backend }));
    expect(facts.probed).toBe(true);
    expect(facts.os).toBeUndefined();
    const section = buildRuntimeContextSection(facts, { platform: "windows" });
    expect(section).toContain("OS: unknown");
    expect(section).toContain("Command tools absent:");
  });
});

// ---------------------------------------------------------------------------
// buildRuntimeContextSection
// ---------------------------------------------------------------------------

describe("buildRuntimeContextSection", () => {
  const facts: RuntimeExecutionFacts = {
    probed: true,
    os: "Linux 6.6.0",
    available: ["bash", "curl", "ffuf", "git", "node", "python3", "sh"],
    missing: PROBE_TOOL_NAMES.filter(
      (t) =>
        !["bash", "curl", "ffuf", "git", "node", "python3", "sh"].includes(t),
    ),
  };

  it("states interpreter and ffuf facts compactly", () => {
    const section = buildRuntimeContextSection(facts, { platform: "posix" });
    expect(section).toContain(
      "OS: Linux 6.6.0 | Shell: bash | Python: available (python3) | Node: available | ffuf: available",
    );
    expect(section).toContain("Command tools present: bash, curl, ffuf");
    expect(section).toContain("Command tools absent:");
  });

  it("carries no session paths — the workspace section owns cwd and file-root context", () => {
    // The section text feeds the trace init record's base prompt, whose
    // hash must stay stable across workspaces.
    const section = buildRuntimeContextSection(facts, { platform: "posix" });
    expect(section).not.toContain("Commands run in");
    expect(section).not.toContain("Native file tools");
    expect(section).not.toMatch(/\/(repo|workspace|helpers)/);
  });

  it("keeps the helper check/run/repair guidance without an operator persona", () => {
    const section = buildRuntimeContextSection(facts, { platform: "posix" });
    expect(section).toContain(
      "Syntax-check or compile new or changed helper scripts",
    );
    expect(section).toContain("repair failures, and rerun");
    expect(section).not.toContain("Operator Mode");
  });

  it("unknown facts never read as absent", () => {
    const section = buildRuntimeContextSection(UNKNOWN_FACTS, {
      platform: "posix",
    });
    expect(section).toContain("unknown (not established");
    expect(section).not.toContain("Command tools absent");
    expect(section).toContain("Verify each tool");
  });

  it("emits no environment variable names or values", () => {
    const section = buildRuntimeContextSection(facts, { platform: "posix" });
    expect(section).not.toContain("SECRET");
    expect(section).not.toContain("PATH");
    expect(section).not.toMatch(/=[A-Za-z0-9]/);
  });

  it("windows guidance verifies with where", () => {
    const section = buildRuntimeContextSection(UNKNOWN_FACTS, {
      platform: "windows",
    });
    expect(section).toContain("where <tool>");
  });
});

describe("buildBundledAssetsSection", () => {
  it("keeps the three wordlist tiers and their guidance", () => {
    const section = buildBundledAssetsSection();
    expect(section).not.toBeNull();
    expect(section).toMatch(/TINY_WORDLIST=\S+tiny\.txt/);
    expect(section).toMatch(/DEFAULT_WORDLIST=\S+common\.txt/);
    expect(section).toMatch(/LARGE_WORDLIST=\S+large\.txt/);
    expect(section).toContain("do NOT probe the filesystem");
    expect(section).toContain("Do NOT assume /usr/share/wordlists/* exists");
  });
});

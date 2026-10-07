// Assembled-prompt regressions for backend-probed runtime context. The final
// system text handed to streamResponse must carry execution facts probed
// through the agent's actual command backend — for the default persona, Fast
// Strike, and custom personas alike — must not advertise host-only wordlist
// assets when execution is remote, and must keep the real SDK result contract
// on the initialization seam (streamReady).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../session";
import type {
  CommandEvent,
  RunOpts,
  ToolBackends,
} from "../../tools/backends/types";
import { FAST_STRIKE_SYSTEM_PROMPT } from "../../workflows/fastStrike";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
import { PROBE_TOOL_NAMES } from "./runtimeContext";

const observed = vi.hoisted(() => ({
  streams: [] as Array<Record<string, unknown>>,
  results: [] as unknown[],
  inits: [] as Array<Record<string, unknown>>,
  order: [] as string[],
}));

vi.mock("../../ai", () => ({
  streamResponse: (opts: Record<string, unknown>) => {
    observed.streams.push(opts);
    observed.order.push("stream");
    const result = {
      fullStream: (async function* () {
        yield { type: "start-step" } as unknown;
      })(),
      response: Promise.resolve({ messages: [] }),
    };
    observed.results.push(result);
    return result;
  },
  normalizeStepUsage: () => ({
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
  }),
}));

vi.mock("./trace", () => ({
  StepTraceWriter: class {
    writeInit(record: Record<string, unknown>) {
      observed.inits.push(record);
      observed.order.push("init");
    }
    recordStep() {}
    markSummarized() {}
  },
}));

function reset(): void {
  observed.streams.length = 0;
  observed.results.length = 0;
  observed.inits.length = 0;
  observed.order.length = 0;
}

afterEach(() => {
  reset();
});

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type RecordedCall = { cmd: string; opts: RunOpts | undefined };

function fakeRemoteBackends(
  respond: () => CommandEvent[] | Promise<CommandEvent[]>,
): { backend: ToolBackends; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const backend = {
    command: {
      platform: "posix" as const,
      run: (cmd: string, opts?: RunOpts) => {
        calls.push({ cmd, opts });
        return (async function* () {
          for (const event of await respond()) yield event;
        })();
      },
    },
  } as unknown as ToolBackends;
  return { backend, calls };
}

const REMOTE_AVAILABLE = ["bash", "curl", "ffuf", "git", "node", "python3"];
const REMOTE_MISSING = PROBE_TOOL_NAMES.filter(
  (t) => !REMOTE_AVAILABLE.includes(t) && t !== "sh",
);
// Decoy: the remote reports `sh` as absent — every POSIX host running this
// test has it — so any host fallback would contradict the report below.
const DECOY_REMOTE_MISSING = [...REMOTE_MISSING, "sh"];

function remoteInventoryEvents(): CommandEvent[] {
  const output = [
    ...REMOTE_AVAILABLE.map((t) => `AVAIL ${t}`),
    ...DECOY_REMOTE_MISSING.map((t) => `MISSING ${t}`),
    "OS: RemoteOS 9.9-test",
  ].join("\n");
  return [
    { type: "stdout", seq: 0, bytes: output },
    { type: "end", exitCode: 0, timedOut: false },
  ];
}

function makeSession(root: string): SessionInfo {
  return {
    id: `ses-rtctx-${Math.random().toString(36).slice(2, 8)}`,
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath: root,
    logsPath: join(root, "logs"),
    findingsPath: join(root, "findings"),
    scratchpadPath: join(root, "scratchpad"),
    pocsPath: join(root, "pocs"),
    config: {},
  } as unknown as SessionInfo;
}

async function withRoot(
  fn: (root: string) => Promise<void> | void,
): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), "apex-rtctx-"));
  try {
    await fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Final assembled prompts
// ---------------------------------------------------------------------------

describe("assembled runtime context in streamResponse prompts", () => {
  it("appends backend facts to the Fast Strike persona", async () => {
    await withRoot(async (root) => {
      const { backend } = fakeRemoteBackends(remoteInventoryEvents);
      const agent = new OffensiveSecurityAgent({
        prompt: "strike the target",
        system: FAST_STRIKE_SYSTEM_PROMPT,
        model: "fixture-model",
        session: makeSession(root),
        mode: "fast-strike",
        activeTools: [],
        backends: backend,
      } as never);
      await agent.streamReady();
      const system = observed.streams[0].system as string;
      // Persona first, facts after — custom personas no longer bypass them.
      expect(system.indexOf(FAST_STRIKE_SYSTEM_PROMPT)).toBe(0);
      expect(system.indexOf("[RUNTIME CONTEXT]")).toBeGreaterThan(
        FAST_STRIKE_SYSTEM_PROMPT.length,
      );
      expect(system).toContain("OS: RemoteOS 9.9-test");
      expect(system).toContain("ffuf: available");
      expect(system).toContain(
        `Command tools present: ${[...REMOTE_AVAILABLE].sort().join(", ")}`,
      );
      // Remote execution must not advertise host-local wordlist paths.
      expect(system).not.toContain("[BUNDLED ASSETS]");
      // Fast Strike enumerates the live registry regardless of the empty
      // input list — and that selection is what earns the runtime probe.
      expect(observed.streams[0].activeTools).toContain("execute_command");
      // Workspace section still follows the facts.
      expect(system.indexOf("# Session Workspace")).toBeGreaterThan(
        system.indexOf("[/RUNTIME CONTEXT]"),
      );
    });
  });

  it("custom personas get the same facts — no bypass", async () => {
    await withRoot(async (root) => {
      const { backend, calls } = fakeRemoteBackends(remoteInventoryEvents);
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        system: "Custom operator persona.",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command", "read_file"],
        backends: backend,
      } as never);
      await agent.streamReady();
      const system = observed.streams[0].system as string;
      expect(system.indexOf("Custom operator persona.")).toBe(0);
      expect(system).toContain("[RUNTIME CONTEXT]");
      expect(system).toContain("ffuf: available");
      expect(calls).toHaveLength(1);
    });
  });

  it("reports the backend's inventory, never the host's (decoy binaries)", async () => {
    await withRoot(async (root) => {
      const { backend, calls } = fakeRemoteBackends(remoteInventoryEvents);
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
        backends: backend,
      } as never);
      await agent.streamReady();
      const system = observed.streams[0].system as string;
      // `sh` is present on the host running this test but reported absent by
      // the remote backend; ffuf is reported present regardless of the host.
      // The prompt must mirror the backend report exactly.
      const absentLine = system
        .split("\n")
        .find((l) => l.startsWith("Command tools absent:"));
      expect(absentLine).toBeDefined();
      expect(absentLine?.split(", ")).toContain("sh");
      expect(system).toContain("Command tools present:");
      expect(
        system
          .split("\n")
          .find((l) => l.startsWith("Command tools present:"))
          ?.split(", "),
      ).toContain("ffuf");
      expect(calls).toHaveLength(1);
    });
  });

  it("local execution probes the real host and advertises bundled assets", async () => {
    await withRoot(async (root) => {
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
      } as never);
      await agent.streamReady();
      const system = observed.streams[0].system as string;
      expect(system).toContain("[RUNTIME CONTEXT]");
      // Workspace paths reach the model via the workspace section, not the
      // runtime facts — and must stay out of the trace init record.
      expect(system).toContain(`The session directory (${root})`);
      expect(observed.inits[0].systemPrompt).not.toContain(root);
      expect(system).toContain("[BUNDLED ASSETS]");
      expect(system).not.toContain("not established");
    });
  });

  it("trace init stays path-free across different workspaces with the same persona and inventory", async () => {
    await withRoot(async (rootA) => {
      const rootB = mkdtempSync(join(tmpdir(), "apex-rtctx-b-"));
      try {
        const { backend } = fakeRemoteBackends(remoteInventoryEvents);
        const common = {
          prompt: "operate",
          model: "fixture-model",
          system: "Shared persona.",
          activeTools: ["execute_command"],
          backends: backend,
        };
        const agentA = new OffensiveSecurityAgent({
          ...common,
          session: makeSession(rootA),
        } as never);
        const agentB = new OffensiveSecurityAgent({
          ...common,
          session: makeSession(rootB),
        } as never);
        await agentA.streamReady();
        await agentB.streamReady();
        // Same persona + same settled inventory → identical init record
        // (stable hash), free of either session's workspace paths.
        expect(observed.inits[1].systemPrompt).toBe(
          observed.inits[0].systemPrompt,
        );
        expect(observed.inits[0].systemPrompt).toContain("[RUNTIME CONTEXT]");
        expect(observed.inits[0].systemPrompt).not.toContain(rootA);
        expect(observed.inits[0].systemPrompt).not.toContain(rootB);
        // The final model prompts still differ by workspace.
        const systemA = observed.streams[0].system as string;
        const systemB = observed.streams[1].system as string;
        expect(systemA).not.toBe(systemB);
        expect(systemA).toContain(rootA);
        expect(systemB).toContain(rootB);
      } finally {
        rmSync(rootB, { recursive: true, force: true });
      }
    });
  });

  it("skips the probe and the section when no execution/file/PoC tools are selected", async () => {
    await withRoot(async (root) => {
      const { backend, calls } = fakeRemoteBackends(remoteInventoryEvents);
      for (const activeTools of [["http_request"], []]) {
        const agent = new OffensiveSecurityAgent({
          prompt: "judge",
          model: "fixture-model",
          session: makeSession(root),
          activeTools,
          backends: backend,
        } as never);
        await agent.streamReady();
        expect(observed.streams.at(-1)?.system).not.toContain(
          "[RUNTIME CONTEXT]",
        );
      }
      // [] means none: no tools, no probe, no runtime facts.
      expect(calls).toHaveLength(0);
      expect(observed.streams[0].activeTools).toEqual(["http_request"]);
      expect(observed.streams[1].activeTools).toEqual([]);
      expect(observed.streams[1].tools).toEqual({});
    });
  });

  it("an abort before start skips the probe but still creates the stream", async () => {
    await withRoot(async (root) => {
      const { backend, calls } = fakeRemoteBackends(remoteInventoryEvents);
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
        backends: backend,
        abortSignal: AbortSignal.abort(),
      } as never);
      await agent.streamReady();
      expect(calls).toHaveLength(0);
      expect(observed.streams).toHaveLength(1);
      expect(observed.streams[0].system).not.toContain("[RUNTIME CONTEXT]");
    });
  });

  it("a failed probe degrades to unknown facts, never absent", async () => {
    await withRoot(async (root) => {
      const { backend } = fakeRemoteBackends(() => [
        { type: "end", exitCode: 1, timedOut: false },
      ]);
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
        backends: backend,
      } as never);
      await agent.streamReady();
      const system = observed.streams[0].system as string;
      expect(system).toContain("unknown (not established");
      expect(system).not.toContain("Command tools absent");
    });
  });

  it("writes the init record once, before the stream, without workspace paths", async () => {
    await withRoot(async (root) => {
      const { backend } = fakeRemoteBackends(remoteInventoryEvents);
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
        backends: backend,
      } as never);
      await agent.streamReady();
      await agent.streamReady();
      expect(observed.order).toEqual(["init", "stream"]);
      expect(observed.inits).toHaveLength(1);
      const init = observed.inits[0];
      expect(init.systemPrompt).toContain("[RUNTIME CONTEXT]");
      expect(init.systemPrompt).not.toContain("# Session Workspace");
      expect(init.activeTools).toEqual(["execute_command"]);
    });
  });
});

// ---------------------------------------------------------------------------
// Initialization seam (public SDK result contract)
// ---------------------------------------------------------------------------

describe("initialization seam", () => {
  it("cold streamResult returns a real SDK result with explicit unknown facts", async () => {
    await withRoot(async (root) => {
      const { backend, calls } = fakeRemoteBackends(remoteInventoryEvents);
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
        backends: backend,
      } as never);
      // Legacy synchronous access: no discovery, no probe, real SDK result.
      expect(agent.streamResult).toBe(observed.results[0]);
      expect(agent.streamResult).toBe(agent.streamResult);
      expect(calls).toHaveLength(0);
      const system = observed.streams[0].system as string;
      expect(system).toContain("[RUNTIME CONTEXT]");
      expect(system).toContain("unknown (not established");
      expect(system).not.toContain("Command tools present:");
      expect(observed.order).toEqual(["init", "stream"]);
    });
  });

  it("cold streamResult on a non-executing agent omits the runtime section entirely", async () => {
    await withRoot(async (root) => {
      const agent = new OffensiveSecurityAgent({
        prompt: "judge",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["http_request"],
      } as never);
      expect(agent.streamResult).toBe(observed.results[0]);
      expect(observed.streams[0].system).not.toContain("[RUNTIME CONTEXT]");
    });
  });

  it("cold streamResult reuses facts a sibling agent already discovered", async () => {
    await withRoot(async (root) => {
      const { backend, calls } = fakeRemoteBackends(remoteInventoryEvents);
      const session = makeSession(root);
      const common = {
        prompt: "operate",
        model: "fixture-model",
        session,
        activeTools: ["execute_command"],
        backends: backend,
      };
      // First agent discovers (same runtime scope: session + backend + cwd).
      await new OffensiveSecurityAgent(common as never).streamReady();
      // Second agent's synchronous escape hatch sees the settled snapshot.
      const second = new OffensiveSecurityAgent({
        ...common,
        prompt: "operate again",
      } as never);
      expect(second.streamResult).toBe(observed.results[1]);
      const system = observed.streams[1].system as string;
      expect(system).toContain("OS: RemoteOS 9.9-test");
      expect(system).toContain("ffuf: available");
      // No third probe: discovery is coalesced per runtime scope.
      expect(calls).toHaveLength(1);
    });
  });

  it("a cold getter racing an in-flight probe never creates a second stream", async () => {
    await withRoot(async (root) => {
      let release: (() => void) | undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const { backend, calls } = fakeRemoteBackends(async () => {
        await gate;
        return remoteInventoryEvents();
      });
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
        backends: backend,
      } as never);
      const ready = agent.streamReady(); // probe in flight
      // Synchronous legacy access while discovery is pending.
      const escaped = agent.streamResult;
      expect(escaped).toBe(observed.results[0]);
      expect(observed.streams[0].system).toContain("unknown (not established");
      release?.();
      await ready;
      // The in-flight discovery must not create a second model stream or a
      // second init record; the escape hatch's stream stands.
      expect(observed.streams).toHaveLength(1);
      expect(observed.inits).toHaveLength(1);
      expect(agent.streamResult).toBe(escaped);
      expect(calls).toHaveLength(1);
    });
  });

  it("direct fullStream iteration initializes and forwards chunks", async () => {
    await withRoot(async (root) => {
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
      } as never);
      const chunks: unknown[] = [];
      for await (const chunk of agent.fullStream) {
        chunks.push(chunk);
      }
      expect(chunks).toEqual([{ type: "start-step" }]);
      expect(observed.order).toEqual(["init", "stream"]);
      // Direct access did not create a second stream.
      expect(observed.streams).toHaveLength(1);
    });
  });

  it("response resolves through the seam", async () => {
    await withRoot(async (root) => {
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["http_request"],
      } as never);
      await expect(agent.response).resolves.toEqual({ messages: [] });
    });
  });

  it("consume() initializes inside the run and completes", async () => {
    await withRoot(async (root) => {
      const { backend, calls } = fakeRemoteBackends(remoteInventoryEvents);
      const agent = new OffensiveSecurityAgent({
        prompt: "operate",
        model: "fixture-model",
        session: makeSession(root),
        activeTools: ["execute_command"],
        backends: backend,
      } as never);
      await agent.consume();
      expect(observed.order[0]).toBe("init");
      expect(observed.order[1]).toBe("stream");
      expect(calls).toHaveLength(1);
      expect(agent.streamResult).toBe(observed.results[0]);
    });
  });
});

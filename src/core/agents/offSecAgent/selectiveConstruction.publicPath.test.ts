// Public-path resource evidence: real tools module, real Zod, real registry;
// passthrough ai.tool spy counts constructions; the stubbed stream captures
// pre-filter arguments only. Measured counts are asserted before map
// metadata so an eager full-catalog constructor behind a name filter fails
// on measured work.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

const observed = vi.hoisted(() => ({
  armed: false,
  constructed: 0,
  streams: [] as Array<{
    tools: Record<string, unknown>;
    activeTools: string[];
  }>,
}));

vi.mock("ai", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    tool: (...args: unknown[]) => {
      const result = (actual.tool as (...a: unknown[]) => unknown)(...args);
      if (observed.armed) observed.constructed++;
      return result;
    },
  };
});

vi.mock("../../ai", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    streamResponse: (options: Record<string, unknown>) => {
      observed.streams.push(options as never);
      return { fullStream: (async function* () {})() };
    },
  };
});

import type { SessionInfo } from "../../session";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

const SPECIALIST_7 = [
  "execute_command",
  "http_request",
  "read_file",
  "list_files",
  "grep",
  "web_search",
  "get_page",
];

function makeSession(root: string, config: Record<string, unknown> = {}) {
  return {
    id: "ses_public_path",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath: root,
    logsPath: join(root, "logs"),
    findingsPath: join(root, "findings"),
    scratchpadPath: join(root, "scratchpad"),
    pocsPath: join(root, "pocs"),
    config,
  } as unknown as SessionInfo;
}

async function withRoot(
  fn: (root: string) => Promise<void> | void,
): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), "apex-pr03-public-path-"));
  try {
    await fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function makeAgent(
  root: string,
  activeTools: string[],
  extraInput: Record<string, unknown> = {},
): OffensiveSecurityAgent {
  const agent = new OffensiveSecurityAgent({
    prompt: "Read the requested file",
    system: "Public-path construction fixture",
    model: "fixture-model",
    session: makeSession(root, extraInput.__config as never),
    activeTools,
    sandbox: {
      type: "linux",
      execute: async () => {
        throw new Error("unexpected sandbox execution in test");
      },
    },
    ...extraInput,
  } as never);
  void agent.streamResult;
  return agent;
}

function reset(): void {
  observed.armed = false;
  observed.constructed = 0;
  observed.streams.length = 0;
}

function stream(at = 0): {
  tools: Record<string, unknown>;
  activeTools: string[];
} {
  const stream = observed.streams[at];
  if (!stream) throw new Error("no captured stream");
  return stream;
}

describe("OffensiveSecurityAgent public-path construction counts", () => {
  it("a specialist-7 selection constructs exactly 7 tools", async () => {
    await withRoot(async (root) => {
      reset();
      observed.armed = true;
      makeAgent(root, SPECIALIST_7);
      observed.armed = false;
      // Measured work first; map metadata after.
      expect(observed.constructed).toBe(7);
      expect(stream().activeTools).toEqual(SPECIALIST_7);
      expect(Object.keys(stream().tools).sort()).toEqual(
        [...SPECIALIST_7].sort(),
      );
    });
  });

  it("an empty selection constructs zero tools", async () => {
    await withRoot(async (root) => {
      reset();
      observed.armed = true;
      makeAgent(root, []);
      observed.armed = false;
      expect(observed.constructed).toBe(0);
      expect(Object.keys(stream().tools)).toEqual([]);
    });
  });

  it("email/SMS gates drop those tools before construction", async () => {
    await withRoot(async (root) => {
      reset();
      observed.armed = true;
      makeAgent(root, [
        "execute_command",
        "email_list_inboxes",
        "send_email",
        "sms_list_messages",
      ]);
      observed.armed = false;
      expect(observed.constructed).toBe(1);
      expect(Object.keys(stream().tools)).toEqual(["execute_command"]);
    });
  });

  it("one browser member constructs only that member (real registry)", async () => {
    await withRoot(async (root) => {
      reset();
      observed.armed = true;
      makeAgent(root, ["browser_click"]);
      observed.armed = false;
      expect(observed.constructed).toBe(1);
      expect(Object.keys(stream().tools)).toEqual(["browser_click"]);
    });
  });

  it("fast-strike full path constructs exactly the gated catalog: 41", async () => {
    await withRoot(async (root) => {
      reset();
      observed.armed = true;
      makeAgent(root, [], { mode: "fast-strike" });
      observed.armed = false;
      const tools = stream().tools;
      expect(observed.constructed).toBe(41);
      expect(Object.keys(tools)).toHaveLength(41);
      expect(tools).toHaveProperty("checkpoint_state");
      expect(tools).not.toHaveProperty("list_workspace_domains");
      expect(tools).not.toHaveProperty("send_email");
      // Real Zod schema on a constructed member, not a stub.
      const schema = (tools.read_file as { inputSchema: z.ZodTypeAny })
        .inputSchema;
      expect(schema).toBeInstanceOf(z.ZodObject);
      expect(
        schema.safeParse({ path: "f.txt", toolCallDescription: "d" }).success,
      ).toBe(true);
    });
  });

  it("selected seven plus five available conditional tools construct twelve", async () => {
    await withRoot(async (root) => {
      reset();
      observed.armed = true;
      const agent = new OffensiveSecurityAgent({
        prompt: "Read the requested file",
        system: "Public-path construction fixture",
        model: "fixture-model",
        session: {
          ...makeSession(root, { taskDriven: true }),
          credentialManager: { listReferences: () => [] },
        },
        activeTools: SPECIALIST_7.concat([
          "read_skill",
          "checkpoint_state",
          "create_task",
          "update_task",
          "list_tasks",
        ]),
        skillsRegistry: { buildCatalog: () => [] },
        sandbox: {
          type: "linux",
          execute: async () => {
            throw new Error("unexpected sandbox execution in test");
          },
        },
      } as never);
      void agent.streamResult;
      observed.armed = false;
      expect(observed.constructed).toBe(12);
      expect(Object.keys(stream().tools)).toHaveLength(12);
    });
  });
});

describe("response injection on the real path", () => {
  it("fast-strike + responseSchema + non-enumerable own response extra still activates the injected response", async () => {
    await withRoot(async (root) => {
      reset();
      const evilResponse = {
        description: "evil extra response",
        inputSchema: z.object({}),
        execute: async () => "evil",
      };
      const extras: Record<string, unknown> = {};
      // A non-enumerable own "response" property: Object.keys never sees
      // it, yet the schema injection must still activate the injected
      // response tool and append "response" to the active name array.
      Object.defineProperty(extras, "response", {
        value: evilResponse,
        enumerable: false,
      });
      observed.armed = true;
      makeAgent(root, [], {
        mode: "fast-strike",
        extraTools: extras,
        responseSchema: z.object({ ok: z.boolean() }),
      });
      observed.armed = false;
      const tools = stream().tools;
      // The injected response tool wins over any extra with that name, and
      // "response" is active in the pre-filter activeTools captured by the
      // stream stub.
      expect(stream().activeTools).toContain("response");
      expect((tools.response as { description?: string }).description).not.toBe(
        "evil extra response",
      );
      expect(tools.response).toBeDefined();
    });
  });

  it("extras append new names after builtins in the tool map without constructing them", async () => {
    await withRoot(async (root) => {
      reset();
      const added = {
        description: "added",
        inputSchema: z.object({}),
        execute: async () => "added",
      };
      observed.armed = true;
      makeAgent(root, ["execute_command"], {
        extraTools: { custom_extra: added },
      });
      observed.armed = false;
      const keys = Object.keys(stream().tools);
      // 1 builtin construction; the extra rides along without a factory.
      expect(observed.constructed).toBe(1);
      expect(keys).toEqual(["execute_command", "custom_extra"]);
      expect(stream().tools.custom_extra).toBe(added);
    });
  });
});

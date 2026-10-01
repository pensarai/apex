import { describe, expect, it } from "vitest";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { LocalBackends } from "./local";
import { defaultPolicy, ToolPolicyDeniedError } from "./policy";
import type { CommandEvent } from "./types";

function scopedCtx(): ToolContext {
  return {
    agentCwd: "/tmp",
    session: {
      id: "ses_test",
      rootPath: "/tmp",
      targets: ["https://example.com"],
    },
  } as ToolContext;
}

function unscopedCtx(): ToolContext {
  return {
    agentCwd: "/tmp",
    session: { id: "ses_test", rootPath: "/tmp" },
  } as ToolContext;
}

describe("defaultPolicy", () => {
  it("allows an in-scope, non-destructive command", async () => {
    const decision = await defaultPolicy.beforeCall({
      backend: "command",
      op: "run",
      args: { command: "ls -la" },
      ctx: unscopedCtx(),
    });
    expect(decision).toEqual({ allow: true });
  });

  it("denies a command that leaves the engagement scope", async () => {
    const decision = await defaultPolicy.beforeCall({
      backend: "command",
      op: "run",
      args: { command: "curl http://evil.com/x" },
      ctx: scopedCtx(),
    });
    expect(decision.allow).toBe(false);
    if (!decision.allow) expect(decision.reason).toMatch(/Scope violation/);
  });

  it("denies a destructive command (block list moved from executeCommand)", async () => {
    const decision = await defaultPolicy.beforeCall({
      backend: "command",
      op: "run",
      args: { command: "rm -rf /" },
      ctx: unscopedCtx(),
    });
    expect(decision.allow).toBe(false);
    if (!decision.allow) {
      expect(decision.reason).toMatch(/Destructive action blocked/);
    }
  });

  it("denies an out-of-scope http request", async () => {
    const decision = await defaultPolicy.beforeCall({
      backend: "http",
      op: "request",
      args: { method: "GET", url: "http://evil.com/" },
      ctx: scopedCtx(),
    });
    expect(decision.allow).toBe(false);
    if (!decision.allow) expect(decision.reason).toMatch(/Scope violation/);
  });

  it("allows an out-of-scope readability (get_page) fetch — research URLs are unscoped", async () => {
    const decision = await defaultPolicy.beforeCall({
      backend: "http",
      op: "request",
      args: { method: "GET", url: "http://evil.com/", extract: "readability" },
      ctx: scopedCtx(),
    });
    expect(decision).toEqual({ allow: true });
  });

  it("allows fs ops by default", async () => {
    const decision = await defaultPolicy.beforeCall({
      backend: "fs",
      op: "read",
      args: { path: "a.txt" },
      ctx: unscopedCtx(),
    });
    expect(decision).toEqual({ allow: true });
  });
});

describe("LocalBackends enforces the policy at the exec boundary", () => {
  it("throws ToolPolicyDeniedError before running a denied command", async () => {
    const { command } = LocalBackends(scopedCtx());
    const iterate = async () => {
      for await (const _ of command.run("curl http://evil.com/x")) {
        void _;
      }
    };
    await expect(iterate()).rejects.toBeInstanceOf(ToolPolicyDeniedError);
  });

  it("honours a custom deny-all policy", async () => {
    const denyAll = {
      beforeCall: () => ({ allow: false as const, reason: "nope" }),
    };
    const { command } = LocalBackends(unscopedCtx(), denyAll);
    const events: CommandEvent[] = [];
    await expect(
      (async () => {
        for await (const e of command.run("ls")) events.push(e);
      })(),
    ).rejects.toThrow(/nope/);
    expect(events).toHaveLength(0);
  });
});

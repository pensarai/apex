import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SandboxExecutionResult, UnifiedSandbox } from "./sandbox";
import { SandboxBrowserBackend } from "./sandboxPlaywright";
import type { ToolContext } from "./types";

const RESULT_START = "__PW_RESULT__";
const RESULT_END = "__PW_END__";

function ok(stdout = "OK"): SandboxExecutionResult {
  return { stdout, stderr: "", exitCode: 0, success: true };
}

/**
 * A fake sandbox: installation/setup probes report ready, and any script
 * execution (`pw_action.js`) resolves with `scriptResult` wrapped in the
 * real result markers `runPlaywrightScript` parses.
 */
function makeFakeSandbox(scriptResult: unknown): {
  sandbox: UnifiedSandbox;
  commands: string[];
} {
  const commands: string[] = [];
  const sandbox: UnifiedSandbox = {
    type: "linux",
    execute: vi.fn(async (command: string) => {
      commands.push(command);
      if (command.includes("pw_action.js")) {
        return ok(
          `${RESULT_START}${JSON.stringify(scriptResult)}${RESULT_END}`,
        );
      }
      return ok();
    }),
  };
  return { sandbox, commands };
}

function makeCtx(sandbox: UnifiedSandbox, rootPath: string): ToolContext {
  return {
    session: { rootPath },
    target: "https://target.example",
    sandbox,
  } as unknown as ToolContext;
}

describe("SandboxBrowserBackend", () => {
  let rootPath: string;

  beforeEach(() => {
    rootPath = mkdtempSync(join(tmpdir(), "apex-sandbox-browser-"));
  });

  afterEach(() => {
    rmSync(rootPath, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("navigates through the sandbox and never calls the host network", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { sandbox, commands } = makeFakeSandbox({
      success: true,
      url: "https://target.example/dashboard",
      title: "Dashboard",
    });
    const backend = SandboxBrowserBackend(makeCtx(sandbox, rootPath));

    const result = await backend.navigate("https://target.example/dashboard");

    expect(result).toEqual({
      success: true,
      url: "https://target.example/dashboard",
      title: "Dashboard",
    });
    expect(commands.some((c) => c.includes("pw_action.js"))).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("surfaces a failed sandbox script as a result, not a throw", async () => {
    const { sandbox } = makeFakeSandbox({
      success: false,
      error: "net::ERR_CONNECTION_REFUSED",
    });
    const backend = SandboxBrowserBackend(makeCtx(sandbox, rootPath));

    const result = await backend.navigate("https://down.example");

    expect(result.success).toBe(false);
    expect(result.error).toBe("net::ERR_CONNECTION_REFUSED");
  });

  it("decodes a screenshot's base64 payload onto the host evidence dir", async () => {
    const png = Buffer.from("fake-png-bytes");
    const { sandbox } = makeFakeSandbox({
      success: true,
      data: png.toString("base64"),
      sandboxPath: "/tmp/evidence/shot.png",
    });
    const backend = SandboxBrowserBackend(makeCtx(sandbox, rootPath));

    const result = await backend.screenshot({ filename: "login-page" });

    expect(result.success).toBe(true);
    const path = result.path;
    if (!path) throw new Error("expected a screenshot path");
    expect(existsSync(path)).toBe(true);
    expect(readFileSync(path)).toEqual(png);
  });

  it("reuses one setup across calls on the same backend instance", async () => {
    const { sandbox, commands } = makeFakeSandbox({ success: true, url: "x" });
    const backend = SandboxBrowserBackend(makeCtx(sandbox, rootPath));

    await backend.navigate("https://target.example/a");
    const afterFirst = commands.filter((c) => c.includes("pw_check.js")).length;
    expect(afterFirst).toBeGreaterThan(0);

    await backend.navigate("https://target.example/b");
    const afterSecond = commands.filter((c) =>
      c.includes("pw_check.js"),
    ).length;
    expect(afterSecond).toBe(afterFirst);
  });

  it("fetches cookies from the sandbox context", async () => {
    const cookies = [
      {
        name: "session",
        value: "abc",
        domain: "target.example",
        path: "/",
        httpOnly: true,
        secure: true,
      },
    ];
    const { sandbox } = makeFakeSandbox({
      success: true,
      cookies,
      cookieHeader: "session=abc",
    });
    const backend = SandboxBrowserBackend(makeCtx(sandbox, rootPath));

    const result = await backend.getCookies();

    expect(result).toEqual({
      success: true,
      cookies,
      cookieHeader: "session=abc",
    });
  });
});

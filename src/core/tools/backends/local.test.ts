import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PerCommandShell } from "../../agents/offSecAgent/tools/perCommandShell";
import type { ReadFileResult } from "../../agents/offSecAgent/tools/readFile";
import { readFile as readFileTool } from "../../agents/offSecAgent/tools/readFile";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { LocalBackends, runLocalProgram } from "./local";
import type { CommandEvent } from "./types";

function makeCtx(over: Partial<ToolContext>): ToolContext {
  const agentCwd = over.agentCwd ?? process.cwd();
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
    ...over,
  } as ToolContext;
}

function tmp(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

async function collect(
  iter: AsyncIterable<CommandEvent>,
): Promise<CommandEvent[]> {
  const events: CommandEvent[] = [];
  for await (const e of iter) events.push(e);
  return events;
}

describe("LocalBackends.fs containment", () => {
  it("rejects an absolute path outside the working directory", async () => {
    const root = tmp("apex-be-");
    const { fs } = LocalBackends(makeCtx({ agentCwd: root }));
    await expect(fs.delete("/etc/hosts")).rejects.toThrow(
      /escapes file workspace/,
    );
  });

  it("rejects a `..` traversal out of the working directory", async () => {
    const root = tmp("apex-be-");
    const { fs } = LocalBackends(makeCtx({ agentCwd: root }));
    await expect(fs.delete("../escape.txt")).rejects.toThrow(
      /escapes file workspace/,
    );
    await expect(fs.delete("a/b/../../../escape.txt")).rejects.toThrow(
      /escapes file workspace/,
    );
  });

  it("blocks escape through a symlinked directory via `..`", async () => {
    const root = tmp("apex-be-");
    const outside = tmp("apex-out-");
    writeFileSync(join(outside, "secret.txt"), "top secret");
    symlinkSync(outside, join(root, "link"));
    const { fs } = LocalBackends(makeCtx({ agentCwd: root }));
    // Lexical resolution of `link/../../secret.txt` climbs above root.
    await expect(fs.delete("link/../../secret.txt")).rejects.toThrow(
      /escapes file workspace/,
    );
  });

  it("surfaces containment failure through apply_patch as a result", async () => {
    const root = tmp("apex-be-");
    const { fs } = LocalBackends(makeCtx({ agentCwd: root }));
    const patch = [
      "--- /dev/null",
      "+++ b//etc/evil.txt",
      "@@ -0,0 +1,1 @@",
      "+pwned",
      "",
    ].join("\n");
    const result = await fs.applyPatch(patch);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes file workspace/);
  });

  it("surfaces containment failure through glob as a result", async () => {
    const root = tmp("apex-be-");
    const { fs } = LocalBackends(makeCtx({ agentCwd: root }));
    const result = await fs.glob("*", { path: "/etc" });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes file workspace/);
  });
});

describe("LocalBackends.fs.read golden parity with read_file", () => {
  it("returns exactly what read_file returns for the whole file", async () => {
    const root = tmp("apex-be-");
    writeFileSync(join(root, "src.ts"), "line1\nline2\nline3\n");
    const ctx = makeCtx({ agentCwd: root });

    const toolResult = (await readFileTool(ctx).execute?.(
      { toolCallDescription: "test", path: "src.ts" },
      { toolCallId: "t", messages: [] },
    )) as ReadFileResult;
    const backendResult = await LocalBackends(ctx).fs.read("src.ts");
    expect(backendResult).toEqual(toolResult);
  });

  it("returns exactly what read_file returns for a line range", async () => {
    const root = tmp("apex-be-");
    writeFileSync(join(root, "src.ts"), "a\nb\nc\nd\ne\n");
    const ctx = makeCtx({ agentCwd: root });

    const toolResult = (await readFileTool(ctx).execute?.(
      { toolCallDescription: "test", path: "src.ts", startLine: 2, endLine: 4 },
      { toolCallId: "t", messages: [] },
    )) as ReadFileResult;
    const backendResult = await LocalBackends(ctx).fs.read("src.ts", {
      startLine: 2,
      endLine: 4,
    });
    expect(backendResult).toEqual(toolResult);
  });

  it("returns exactly what read_file returns for a missing file", async () => {
    const root = tmp("apex-be-");
    const ctx = makeCtx({ agentCwd: root });

    const toolResult = (await readFileTool(ctx).execute?.(
      { toolCallDescription: "test", path: "nope.ts" },
      { toolCallId: "t", messages: [] },
    )) as ReadFileResult;
    const backendResult = await LocalBackends(ctx).fs.read("nope.ts");
    expect(backendResult).toEqual(toolResult);
  });
});

describe("LocalBackends.command streaming", () => {
  let shell: PerCommandShell | undefined;

  afterEach(() => {
    shell?.dispose();
    shell = undefined;
  });

  it("emits start, monotonic-seq data events, then end", async () => {
    const root = tmp("apex-be-");
    shell = new PerCommandShell({ cwd: root });
    const { command } = LocalBackends(
      makeCtx({ agentCwd: root, commandShell: shell }),
    );

    const events = await collect(
      command.run("printf 'a\\n'; printf 'b\\n'; printf 'c\\n'"),
    );

    expect(events[0]).toEqual({ type: "start" });
    const end = events[events.length - 1];
    expect(end.type).toBe("end");
    if (end.type === "end") {
      expect(end.exitCode).toBe(0);
      expect(end.timedOut).toBe(false);
    }

    const seqs = events
      .filter(
        (e): e is Extract<CommandEvent, { type: "stdout" | "stderr" }> =>
          e.type === "stdout" || e.type === "stderr",
      )
      .map((e) => e.seq);
    expect(seqs).toEqual([...seqs].sort((x, y) => x - y));
    for (let i = 0; i < seqs.length; i++) expect(seqs[i]).toBe(i);

    const stdout = events
      .filter(
        (e): e is Extract<CommandEvent, { type: "stdout" }> =>
          e.type === "stdout",
      )
      .map((e) => e.bytes)
      .join("");
    expect(stdout).toContain("a");
    expect(stdout).toContain("b");
    expect(stdout).toContain("c");
  });

  it("ends with timedOut when the timeout fires", async () => {
    const root = tmp("apex-be-");
    shell = new PerCommandShell({ cwd: root });
    const { command } = LocalBackends(
      makeCtx({ agentCwd: root, commandShell: shell }),
    );

    const events = await collect(command.run("sleep 5", { timeoutSeconds: 1 }));
    const end = events[events.length - 1];
    expect(end.type).toBe("end");
    if (end.type === "end") {
      expect(end.timedOut).toBe(true);
      expect(end.exitCode).toBe(124);
    }
  });

  it("emits every authoritative stdout byte even when nothing was live-streamed", async () => {
    // A mock commandShell whose `execute` never calls the onData
    // callback (as real short-lived tail -f races sometimes do) — the
    // authoritative `res.stdout` must still reach the event stream.
    const root = tmp("apex-be-");
    const commandShell = {
      execute: async () => ({ exitCode: 0, stdout: "full output", stderr: "" }),
    } as unknown as PerCommandShell;
    const { command } = LocalBackends(
      makeCtx({ agentCwd: root, commandShell }),
    );

    const events = await collect(command.run("echo unused"));
    const stdout = events
      .filter(
        (e): e is Extract<CommandEvent, { type: "stdout" }> =>
          e.type === "stdout",
      )
      .map((e) => e.bytes)
      .join("");
    expect(stdout).toBe("full output");
  });
});

describe("LocalBackends.http destructive guard", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("classifies session headers, not just the agent's", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const ctx = makeCtx({});
    ctx.session.targets = ["https://app.test"];
    ctx.session.config = {
      headers: { "X-HTTP-Method-Override": "DELETE" },
    } as NonNullable<ToolContext["session"]["config"]>;

    await expect(
      LocalBackends(ctx).http.request({
        url: "https://app.test/api/items/1",
        method: "POST",
      }),
    ).rejects.toThrow();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("LocalBackends.http redirect policy", () => {
  it("blocks an out-of-scope sandbox redirect before a second request", async () => {
    const execute = vi.fn(async (command: string) => {
      const nonce = command.match(/__APEX_([0-9a-f]+)_CURL_EXIT_/)?.[1];
      return {
        success: true,
        exitCode: 0,
        stdout: Buffer.from(
          `HTTP/1.1 302 Found\r\nLocation: https://outside.example/admin\r\n\r\n\n__APEX_${nonce}_CURL_EXIT_0\n`,
        ).toString("base64"),
        stderr: "",
      };
    });
    const ctx = makeCtx({
      target: "https://target.example",
      sandbox: {
        type: "linux",
        execute,
      } as unknown as NonNullable<ToolContext["sandbox"]>,
    });

    const result = await LocalBackends(ctx).http.request({
      url: "https://target.example/start",
      method: "GET",
      followRedirects: true,
    });

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/scope violation/i),
    });
    expect(execute).toHaveBeenCalledOnce();
  });
});

describe("LocalBackends.http timeout", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  function slowFetch(ms: number) {
    return vi.fn(
      (_url: string, init: RequestInit) =>
        new Promise<Response>((resolve, reject) => {
          const timer = setTimeout(() => resolve(new Response("ok")), ms);
          init.signal?.addEventListener("abort", () => {
            clearTimeout(timer);
            reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
          });
        }),
    );
  }

  it("waits indefinitely unless the caller sets timeoutMs", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", slowFetch(15_000));
    const { http } = LocalBackends(makeCtx({}));

    const untimed = http.request({ url: "https://app.test/", method: "GET" });
    const timed = http.request(
      { url: "https://app.test/", method: "GET" },
      { timeoutMs: 10_000 },
    );
    await vi.advanceTimersByTimeAsync(15_000);

    expect((await untimed).success).toBe(true);
    expect(await timed).toMatchObject({
      success: false,
      error: "Request timeout after 10000ms",
    });
  });
});

it("preserves UTF-8 codepoints split across streamed stdout chunks", async () => {
  const events = await collect(
    runLocalProgram(
      makeCtx({}),
      "UTF-8 stdout regression",
      process.execPath,
      [
        "-e",
        "process.stdout.write(Buffer.from([0xf0,0x9f])); setTimeout(()=>process.stdout.write(Buffer.from([0x98,0x80])),50)",
      ],
      { timeoutSeconds: 5 },
    ),
  );
  expect(
    events
      .filter((event) => event.type === "stdout")
      .map((event) => event.bytes)
      .join(""),
  ).toBe("😀");
  expect(events.at(-1)).toMatchObject({
    type: "end",
    exitCode: 0,
    timedOut: false,
  });
});

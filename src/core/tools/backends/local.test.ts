import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PerCommandShell } from "../../agents/offSecAgent/tools/perCommandShell";
import type { ReadFileResult } from "../../agents/offSecAgent/tools/readFile";
import { readFile as readFileTool } from "../../agents/offSecAgent/tools/readFile";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { createLocalResearchFetchToken } from "../../http/researchFetchToken";
import { RateLimiter } from "../../services/rateLimiter";
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

describe("LocalBackends local research capabilities", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redeems a URL-bound Brave result without forwarding target credentials", async () => {
    const externalUrl = "https://research.example/advisory";
    const fetchMock = vi.fn(
      async () =>
        new Response("<html><body>Advisory</body></html>", {
          headers: { "content-type": "text/html" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const ctx = makeCtx({ target: "https://target.example" });
    ctx.session._rateLimiter = new RateLimiter({ requestsPerSecond: 1 });
    const acquireSlot = vi.spyOn(ctx.session._rateLimiter, "acquireSlot");
    ctx.session.config = {
      headers: { Authorization: "Bearer target-secret" },
      scopeConstraints: {
        allowedHosts: ["target.example"],
        strictScope: true,
      },
    };

    const result = await LocalBackends(ctx).http.request({
      url: externalUrl,
      method: "GET",
      extract: "readability",
      fetchToken: createLocalResearchFetchToken(externalUrl),
    });

    expect(result).toMatchObject({ success: true, url: externalUrl });
    expect(fetchMock).toHaveBeenCalledWith(externalUrl, {
      method: "GET",
      redirect: "manual",
      signal: expect.any(AbortSignal),
    });
    expect(acquireSlot).not.toHaveBeenCalled();
  });
});

describe("LocalBackends.http redirect policy", () => {
  it.each([
    false,
    true,
  ])("charges only authorized sandbox redirects (in scope=%s)", async (inScope) => {
    const execute = vi.fn(async (command: string) => {
      const nonce = command.match(/__APEX_([0-9a-f]+)_CURL_EXIT_/)?.[1];
      const response = command.includes("/start")
        ? `HTTP/1.1 302 Found\r\nLocation: https://${inScope ? "target" : "outside"}.example/admin\r\n\r\n`
        : "HTTP/1.1 200 OK\r\n\r\n";
      return {
        success: true,
        exitCode: 0,
        stdout: Buffer.from(
          `${response}\n__APEX_${nonce}_CURL_EXIT_0\n`,
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
    ctx.session._rateLimiter = new RateLimiter({ requestsPerSecond: 1 });
    const acquireSlot = vi
      .spyOn(ctx.session._rateLimiter, "acquireSlot")
      .mockResolvedValue(true);

    const result = await LocalBackends(ctx).http.request({
      url: "https://target.example/start",
      method: "GET",
      followRedirects: true,
    });

    expect(result).toMatchObject(
      inScope
        ? { success: true, status: 200 }
        : {
            success: false,
            error: expect.stringMatching(/scope violation/i),
          },
    );
    expect(execute).toHaveBeenCalledTimes(inScope ? 2 : 1);
    expect(acquireSlot).toHaveBeenCalledTimes(inScope ? 2 : 1);
  });

  it.each([
    { status: 303, method: "HEAD", expected: "HEAD", body: undefined },
    { status: 301, method: "PUT", expected: "PUT", body: "put-body" },
    {
      status: 302,
      method: "PATCH",
      expected: "PATCH",
      body: "patch-body",
    },
  ] as const)("preserves $method across $status like the shared redirect primitive", async ({
    status,
    method,
    expected,
    body,
  }) => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response("", {
          status,
          headers: { location: "https://target.example/final" },
        }),
      )
      .mockResolvedValueOnce(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);
    const ctx = makeCtx({ target: "https://target.example" });
    ctx.session.config = {
      allowDestructiveActions: true,
      scopeConstraints: {
        allowedHosts: ["target.example"],
        allowedPorts: [443],
        strictScope: true,
      },
    };

    try {
      await LocalBackends(ctx).http.request({
        url: "https://target.example/start",
        method,
        body,
        followRedirects: true,
      });

      const redirectedInit = fetchMock.mock.calls[1]?.[1] as RequestInit;
      expect(redirectedInit.method).toBe(expected);
      expect(redirectedInit.body).toBe(body);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("LocalBackends.http queued rate limits", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it.each([
    { sandbox: false, stop: "aborted" },
    { sandbox: true, stop: "aborted" },
    { sandbox: false, stop: "timeout" },
    { sandbox: true, stop: "timeout" },
  ] as const)("does not dispatch after $stop while throttled (sandbox=$sandbox)", async ({
    sandbox,
    stop,
  }) => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "Date", "performance"],
    });
    const fetchSpy = vi.fn(async () => new Response("ok"));
    const execute = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const controller = new AbortController();
    const ctx = makeCtx({
      target: "https://target.example",
      abortSignal: controller.signal,
      ...(sandbox
        ? {
            sandbox: { type: "linux", execute } as unknown as NonNullable<
              ToolContext["sandbox"]
            >,
          }
        : {}),
    });
    ctx.session._rateLimiter = new RateLimiter({ requestsPerSecond: 1 });
    await ctx.session._rateLimiter.acquireSlot();

    const pending = LocalBackends(ctx).http.request(
      { url: "https://target.example/queued" },
      stop === "timeout" ? { timeoutMs: 50 } : undefined,
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();

    if (stop === "aborted") controller.abort();
    else await vi.advanceTimersByTimeAsync(50);

    expect(await pending).toMatchObject({
      success: false,
      capture: { complete: false, stopReason: stop },
    });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
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

describe("LocalBackends.repoClone", () => {
  let shell: PerCommandShell | undefined;

  afterEach(() => {
    shell?.dispose();
    shell = undefined;
  });

  function sourceRepo(): string {
    const repo = tmp("apex-repo-src-");
    const git = (...args: string[]) =>
      execFileSync("git", args, { cwd: repo, stdio: "pipe" });
    git("init", "-b", "main");
    git("config", "user.name", "Fixture");
    git("config", "user.email", "fixture@example.test");
    writeFileSync(join(repo, "marker"), "main");
    git("add", ".");
    git("commit", "-m", "main");
    git("checkout", "-b", "release");
    writeFileSync(join(repo, "marker"), "release");
    git("commit", "-am", "release");
    git("checkout", "main");
    return repo;
  }

  function cloner(root: string) {
    shell = new PerCommandShell({ cwd: root });
    const { repoClone } = LocalBackends(
      makeCtx({ agentCwd: root, commandShell: shell }),
    );
    if (!repoClone) throw new Error("LocalBackends must provide repoClone");
    return repoClone;
  }

  it("clones a connected repo at the requested branch under the workspace", async () => {
    const root = tmp("apex-be-");
    const repoClone = cloner(root);
    const result = await repoClone.clone({
      repoUrl: sourceRepo(),
      ref: "release",
      dest: "repos/fixture",
    });
    expect(result).toEqual({
      success: true,
      path: join(root, "repos/fixture"),
    });
    expect(readFileSync(join(root, "repos/fixture/marker"), "utf8")).toBe(
      "release",
    );
  });

  it("reuses an existing clone instead of failing on a second call", async () => {
    const root = tmp("apex-be-");
    const repoClone = cloner(root);
    const repoUrl = sourceRepo();
    const request = { repoUrl, dest: "repos/fixture" };
    expect((await repoClone.clone(request)).success).toBe(true);
    expect((await repoClone.clone(request)).success).toBe(true);
  });

  it("reports a failed clone as a structured error", async () => {
    const root = tmp("apex-be-");
    const repoClone = cloner(root);
    const result = await repoClone.clone({
      repoUrl: join(root, "does-not-exist"),
      dest: "repos/missing",
    });
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

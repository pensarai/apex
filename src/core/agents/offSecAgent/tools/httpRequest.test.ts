import { exec } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  promptInjectionRef,
  StaticPromptInjectionLibrary,
} from "../../../prompt-injections";
import { RateLimiter } from "../../../services/rateLimiter";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { type HttpRequestResult, httpRequest } from "./httpRequest";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

const TEST_LIBRARY = new StaticPromptInjectionLibrary([
  {
    id: "pi.direct.override",
    name: "Direct Override",
    category: "instruction-hijack",
    description: "Safe metadata for a direct override test.",
    tags: ["baseline"],
    deliveryHints: ["json-body"],
    expectedObservation: "The system should preserve hierarchy.",
    payload: "TEST PAYLOAD: direct override",
  },
]);

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: ["https://example.com"],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    target: "https://example.com",
    ...overrides,
  };
}

describe("httpRequest prompt injection refs", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves body refs only at execution time and redacts echoed payloads", async () => {
    const id = "pi.direct.override";
    const payload = TEST_LIBRARY.getPayload(id)!;
    let capturedBody: BodyInit | null | undefined;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        capturedBody = init?.body;
        return new Response(`server echoed ${String(init?.body)}`, {
          status: 200,
          headers: { "x-echo": String(init?.body) },
        });
      }),
    );

    const tool = httpRequest(makeCtx({ promptInjectionLibrary: TEST_LIBRARY }));
    const result = (await tool.execute?.(
      {
        url: "https://example.com/chat",
        method: "POST",
        body: promptInjectionRef(id),
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Send hidden prompt-injection reference",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(capturedBody).toBe(payload);
    expect(result.success).toBe(true);
    expect(result.body).toContain(`[PROMPT_INJECTION:${id}]`);
    expect(result.body).not.toContain(payload);
    expect(result.headers["x-echo"]).toBe(`[PROMPT_INJECTION:${id}]`);
  });

  it("does not resolve inline placeholder strings in request bodies", async () => {
    let capturedBody: BodyInit | null | undefined;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        capturedBody = init?.body;
        return new Response("ok", { status: 200 });
      }),
    );

    const tool = httpRequest(makeCtx({ promptInjectionLibrary: TEST_LIBRARY }));
    await tool.execute?.(
      {
        url: "https://example.com/chat",
        method: "POST",
        body: "payload={{prompt_injection:pi.encoded.override}}",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Send literal placeholder text",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    expect(capturedBody).toBe(
      "payload={{prompt_injection:pi.encoded.override}}",
    );
  });
});

describe("httpRequest rate limiting", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  function ctxWithLimiter() {
    const limiter = new RateLimiter({ requestsPerSecond: 5 });
    const acquireSlot = vi
      .spyOn(limiter, "acquireSlot")
      .mockResolvedValue(true);
    const ctx = makeCtx();
    ctx.session._rateLimiter = limiter;
    return { ctx, acquireSlot };
  }

  it("acquires exactly one rate-limit slot per dispatched request", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("ok", { status: 200 })),
    );
    const { ctx, acquireSlot } = ctxWithLimiter();

    await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Rate-limited GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    expect(acquireSlot).toHaveBeenCalledTimes(1);
  });

  it("does not consume a slot when the request is out of scope", async () => {
    const fetchSpy = vi.fn(async () => new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const { ctx, acquireSlot } = ctxWithLimiter();

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://evil.com/",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Out-of-scope GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(acquireSlot).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("acquires one slot before the sandbox curl dispatch", async () => {
    const { ctx, acquireSlot } = ctxWithLimiter();
    const execute = vi.fn(async () => ({
      success: true,
      exitCode: 0,
      stdout: "HTTP/1.1 200 OK\n\n",
      stderr: "",
    }));
    ctx.sandbox = { execute } as unknown as ToolContext["sandbox"];

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Sandbox GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(acquireSlot).toHaveBeenCalledTimes(1);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(result.status).toBe(200);
  });

  it("deletes the request-body temp file after a sandbox POST", async () => {
    const { ctx } = ctxWithLimiter();
    const commands: string[] = [];
    const execute = vi.fn(async (command: string) => {
      commands.push(command);
      return {
        success: true,
        exitCode: 0,
        stdout: "HTTP/1.1 200 OK\n\n",
        stderr: "",
      };
    });
    ctx.sandbox = { execute } as unknown as ToolContext["sandbox"];

    await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "POST",
        body: "hello=world",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Sandbox POST",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    const bodyFile = commands
      .join("\n")
      .match(/\/tmp\/apex_http_body_[^\s"']+\.txt/)?.[0];
    expect(bodyFile).toBeDefined();
    // The temp file is both written (curl --data-binary) and removed.
    expect(commands.some((c) => c.includes(`rm -f ${bodyFile}`))).toBe(true);
  });

  it("returns an aborted result without dispatching when already aborted", async () => {
    const fetchSpy = vi.fn(async () => new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const { ctx } = ctxWithLimiter();
    const controller = new AbortController();
    controller.abort();
    ctx.abortSignal = controller.signal;

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 1000,
        toolCallDescription: "Aborted GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: controller.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("aborted");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

// Full-lifetime liveness: the request deadline must cover the body read, not
// just the headers, and the body must be byte-bounded while streaming. All
// fixtures are synthetic streams — no network.
describe("httpRequest body liveness", () => {
  const enc = new TextEncoder();
  const scratchDirs: string[] = [];

  afterEach(() => {
    vi.unstubAllGlobals();
    for (const dir of scratchDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function ctxWithScratchLogs(overrides: Partial<ToolContext> = {}) {
    const scratchDir = mkdtempSync(join(tmpdir(), "apex-httpreq-test-"));
    scratchDirs.push(scratchDir);
    const base = makeCtx();
    return makeCtx({
      ...overrides,
      session: {
        ...base.session,
        rootPath: scratchDir,
        logsPath: join(scratchDir, "logs"),
      } as SessionInfo,
    });
  }

  function savedPathFrom(body: string): string {
    const m = body.match(/(?:partial|full) response saved to (.+?)\)\./);
    if (!m) {
      throw new Error(`no saved-file pointer in body: ${body.slice(0, 200)}`);
    }
    return m[1];
  }

  function stalledBodyStream(first: string): ReadableStream<Uint8Array> {
    return new ReadableStream({
      start(c) {
        c.enqueue(enc.encode(first));
        // Never enqueues again and never closes — a stalling body.
      },
    });
  }

  it("fails with a bounded timeout when the body stalls after headers arrive", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(stalledBodyStream("headers-arrived-body-stalls"), {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/stall",
        method: "GET",
        followRedirects: false,
        timeout: 100,
        toolCallDescription: "GET with a stalling body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("Request timeout after 100ms");
  }, 5_000);

  it("bounds an endless body at the byte cap, cancels the stream, and still saves the capture", async () => {
    const CAP = 5 * 1024 * 1024;
    const chunk = new Uint8Array(64 * 1024).fill(65); // "A" * 64KiB
    let delivered = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        delivered += chunk.byteLength;
        c.enqueue(chunk);
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/endless",
        method: "GET",
        followRedirects: false,
        timeout: 30_000,
        toolCallDescription: "GET with an endless body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    // Streaming cap: the tool stopped reading well before the fixture could
    // deliver an unbounded body (response.text() would never finish here).
    // Slack covers the stream's one-chunk readahead plus the cap-boundary peek.
    expect(delivered).toBeLessThanOrEqual(CAP + 4 * chunk.byteLength);
    // The underlying stream was actually cancelled, not just abandoned.
    expect(cancelled).toBe(true);
    // Incomplete download is explicit to the caller — never "full response saved".
    expect(result.body).toContain("INCOMPLETE");
    expect(result.body).not.toContain("full response saved");
    const saved = readFileSync(savedPathFrom(result.body), "utf-8");
    expect(saved.length).toBe(CAP);
    expect(/^A+$/.test(saved)).toBe(true);
  }, 10_000);

  it("caps a body delivered as many tiny chunks plus one huge chunk, byte-exactly", async () => {
    const CAP = 5 * 1024 * 1024;
    const tinyCount = 5_000;
    const tiny = new Uint8Array([65]); // "A"
    const huge = new Uint8Array(6 * 1024 * 1024).fill(66); // "B" * 6 MiB
    let cancelled = false;
    let tinyDelivered = 0;
    let hugeDelivered = false;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        if (tinyDelivered < tinyCount) {
          tinyDelivered++;
          c.enqueue(tiny);
        } else if (!hugeDelivered) {
          hugeDelivered = true;
          c.enqueue(huge);
        }
        // else: stall — no further chunks, no close.
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/adversarial",
        method: "GET",
        followRedirects: false,
        timeout: 10_000,
        toolCallDescription: "GET with adversarial chunking",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    expect(cancelled).toBe(true);
    // The capture is byte-exact: every tiny chunk landed, then the huge chunk
    // filled the remaining room to the cap — one owned buffer, no loss.
    const saved = readFileSync(savedPathFrom(result.body), "utf-8");
    expect(saved.length).toBe(CAP);
    expect(saved.startsWith("A".repeat(tinyCount))).toBe(true);
    expect(saved.substring(tinyCount)).toBe("B".repeat(CAP - tinyCount));
  }, 10_000);

  it("completes despite a body stream whose cancel never settles", async () => {
    const chunk = new Uint8Array(64 * 1024).fill(65); // "A" * 64KiB
    let cancelCalled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        c.enqueue(chunk);
      },
      cancel() {
        cancelCalled = true;
        return new Promise(() => {}); // never settles
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const started = Date.now();
    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/hanging-cancel",
        method: "GET",
        followRedirects: false,
        timeout: 10_000,
        toolCallDescription: "GET whose stream cancel never settles",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    // The cap path invoked the real cancel but never awaited it — completion
    // must not depend on the stream's cancel promise.
    expect(result.success).toBe(true);
    expect(cancelCalled).toBe(true);
    expect(Date.now() - started).toBeLessThan(2_000);
  }, 5_000);

  it("aborts promptly when the host aborts between headers and body registration", async () => {
    const ac = new AbortController();
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode("partial"));
        // Never completes on its own.
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const res = new Response(body, { status: 200 });
        ac.abort(); // after headers exist, before the body reader registers
        return res;
      }),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/pre-aborted",
        method: "GET",
        followRedirects: false,
        timeout: 10_000,
        toolCallDescription: "GET pre-aborted between headers and body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("Request aborted by user");
    expect(cancelled).toBe(true);
  }, 5_000);

  it("does not report success for a curl --max-time cutoff (exit 28) with partial 200 output", async () => {
    // Sandbox adapter contract for the bounded pipeline: the sandbox reports
    // head's exit (0/success); curl's real exit rides the nonce marker.
    const execute = vi.fn(async (command: string) => {
      const nonce = command.match(/__APEX_([0-9a-f]+)_CURL_EXIT_/)?.[1];
      return {
        success: true,
        exitCode: 0,
        stdout:
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial" +
          `\n__APEX_${nonce}_CURL_EXIT_28\n`,
        stderr: "",
      };
    });
    const ctx = ctxWithScratchLogs({
      sandbox: { execute } as unknown as ToolContext["sandbox"],
    });

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/slow-download",
        method: "GET",
        followRedirects: false,
        timeout: 1_000,
        toolCallDescription: "GET cut off by curl --max-time",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("curl exited 28");
    // Partial metadata is retained so the caller sees what actually arrived.
    expect(result.status).toBe(200);
    expect(result.headers["content-type"]).toBe("text/plain");
    expect(result.body).toContain("partial");
    expect(result.body).toContain("INCOMPLETE");
  });

  it("preserves raw CRLF bytes in a sandbox response body", async () => {
    const execute = vi.fn(async (command: string) => {
      const nonce = command.match(/__APEX_([0-9a-f]+)_CURL_EXIT_/)?.[1];
      return {
        success: true,
        exitCode: 0,
        stdout:
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nline1\r\nline2\r\n" +
          `\n__APEX_${nonce}_CURL_EXIT_0\n`,
        stderr: "",
      };
    });
    const ctx = ctxWithScratchLogs({
      sandbox: { execute } as unknown as ToolContext["sandbox"],
    });

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/crlf",
        method: "GET",
        followRedirects: false,
        timeout: 1_000,
        toolCallDescription: "Sandbox GET with CRLF body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    expect(result.headers["content-type"]).toBe("text/plain");
    // The body keeps its raw bytes — no line-ending normalization.
    expect(result.body).toBe("line1\r\nline2\r\n");
  });

  it("reports success for a complete sandbox transfer with a clean curl exit marker", async () => {
    const execute = vi.fn(async (command: string) => {
      const nonce = command.match(/__APEX_([0-9a-f]+)_CURL_EXIT_/)?.[1];
      return {
        success: true,
        exitCode: 0,
        stdout: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok-body\n__APEX_${nonce}_CURL_EXIT_0\n`,
        stderr: "",
      };
    });
    const ctx = ctxWithScratchLogs({
      sandbox: { execute } as unknown as ToolContext["sandbox"],
    });

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/ok",
        method: "GET",
        followRedirects: false,
        timeout: 1_000,
        toolCallDescription: "Complete sandbox GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(200);
    expect(result.body).toBe("ok-body");
  });

  it("treats marker-less sandbox output as capped and incomplete", async () => {
    // head cut the stream at the cap: curl SIGPIPE'd before writing its exit
    // marker, so the output carries no trustworthy exit status.
    const CAP = 5 * 1024 * 1024;
    const execute = vi.fn(async () => ({
      success: true,
      exitCode: 0,
      stdout: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n${"A".repeat(CAP)}`,
      stderr: "",
    }));
    const ctx = ctxWithScratchLogs({
      sandbox: { execute } as unknown as ToolContext["sandbox"],
    });

    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/endless-download",
        method: "GET",
        followRedirects: false,
        timeout: 30_000,
        toolCallDescription: "Sandbox GET capped by head",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("capped");
    expect(result.body).toContain("INCOMPLETE");
    expect(readFileSync(savedPathFrom(result.body), "utf-8").length).toBe(CAP);
  }, 10_000);

  it("stops an oversized producer in the sandbox and returns bounded output (real loopback)", async () => {
    const CAP = 5 * 1024 * 1024;
    let writes = 0;
    let connectionClosed = false;
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" }); // chunked
      const timer = setInterval(() => {
        writes++;
        res.write("x".repeat(64 * 1024));
      }, 5);
      res.on("close", () => {
        connectionClosed = true;
        clearInterval(timer);
      });
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const port = (server.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/endless`;

    // Real child-process shell adapter: mirrors the sandbox contract
    // (command → stdout/stderr/exitCode) using the local toolchain.
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: (command, opts) =>
        new Promise((resolve) => {
          exec(
            command,
            {
              timeout: (opts?.timeout ?? 30) * 1_000,
              maxBuffer: 16 * 1024 * 1024,
              encoding: "utf8",
            },
            (error, stdout, stderr) => {
              resolve({
                stdout: stdout ?? "",
                stderr: stderr ?? "",
                exitCode:
                  typeof error?.code === "number" ? error.code : error ? 1 : 0,
                success: !error,
              });
            },
          );
        }),
    };

    try {
      const base = makeCtx();
      const ctx = ctxWithScratchLogs({
        sandbox,
        target: url,
        session: {
          ...base.session,
          targets: [url],
        } as SessionInfo,
      });

      const started = Date.now();
      const result = (await httpRequest(ctx).execute?.(
        {
          url,
          method: "GET",
          followRedirects: false,
          timeout: 20_000,
          toolCallDescription: "Endless loopback download through sandbox curl",
        },
        { toolCallId: "tc_test", messages: [], abortSignal: undefined },
      )) as HttpRequestResult;
      const elapsed = Date.now() - started;

      // The call must not hang: the pipeline finishes on its own once head
      // hits the cap and curl SIGPIPEs.
      expect(elapsed).toBeLessThan(10_000);
      // The producer was actually stopped: the connection close event may
      // lag the tool result on the event loop, so wait for it (bounded).
      const closeDeadline = Date.now() + 3_000;
      while (!connectionClosed && Date.now() < closeDeadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(connectionClosed).toBe(true);
      const writesAtReturn = writes;
      await new Promise((r) => setTimeout(r, 300));
      expect(writes).toBe(writesAtReturn);
      // …and the total produced stayed bounded (cap + socket-buffer slack) —
      // an endless producer with a live consumer would grow without bound.
      expect(writes).toBeLessThan(500);
      // SDK-visible output is bounded by the pipeline, not by post-hoc
      // truncation: the saved capture is exactly at the cap and incomplete.
      expect(result.success).toBe(false);
      expect(result.error).toContain("capped");
      const saved = readFileSync(savedPathFrom(result.body), "utf-8");
      expect(saved.length).toBeLessThanOrEqual(CAP);
      expect(saved.length).toBeGreaterThan(CAP - 64 * 1024);
    } finally {
      server.close();
    }
  }, 30_000);

  it("reports failure when the body stream errors mid-read", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode("partial;"));
        c.error(new Error("synthetic connection reset"));
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/broken",
        method: "GET",
        followRedirects: false,
        timeout: 2_000,
        toolCallDescription: "GET with a broken body stream",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("synthetic connection reset");
  });

  it("fails and cancels the stream when the host aborts mid-body", async () => {
    const ac = new AbortController();
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode("<html>partial"));
        setTimeout(() => ac.abort(), 50);
        // Body never completes on its own — only the abort can end this read.
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/slow",
        method: "GET",
        followRedirects: false,
        timeout: 30_000,
        toolCallDescription: "GET aborted by the host mid-body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("Request aborted by user");
    expect(cancelled).toBe(true);
  }, 5_000);

  it("returns a successful body and preserves inline/save-file truncation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("ok-body", { status: 200 })),
    );

    const small = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/ok",
        method: "GET",
        followRedirects: false,
        timeout: 2_000,
        toolCallDescription: "Small GET",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(small.success).toBe(true);
    expect(small.body).toBe("ok-body");

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("x".repeat(6_000), { status: 200 })),
    );

    const large = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/large",
        method: "GET",
        followRedirects: false,
        timeout: 2_000,
        toolCallDescription: "GET with a save-file-sized body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(large.success).toBe(true);
    expect(large.body.startsWith("xxxx")).toBe(true);
    expect(large.body).toContain("full response saved to");
    expect(readFileSync(savedPathFrom(large.body), "utf-8")).toBe(
      "x".repeat(6_000),
    );
  });
});

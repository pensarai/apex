import { exec } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
    expect(result.error).toContain("Request timeout after 100ms");
    // Timeout after partial data: status/headers and the bounded partial body
    // survive, marked incomplete — never discarded, never a clean success.
    expect(result.status).toBe(200);
    expect(result.headers["content-type"]).toBe("text/html");
    expect(result.body).toContain("headers-arrived-body-stalls");
    expect(result.body).toContain("INCOMPLETE");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "timeout",
      capturedBytes: "headers-arrived-body-stalls".length,
      capturedBytesBasis: "raw",
    });
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

    expect(result.success).toBe(false);
    // A capped capture is not an ordinary success even though the status is
    // 200 — the structured capture says exactly why.
    expect(result.error).toContain("capped");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "byte-cap",
      capturedBytes: CAP,
      capturedBytesBasis: "raw",
    });
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

    expect(result.success).toBe(false);
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "byte-cap",
      capturedBytes: CAP,
      capturedBytesBasis: "raw",
    });
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
    expect(result.success).toBe(false);
    expect(result.capture).toMatchObject({
      stopReason: "byte-cap",
      capturedBytesBasis: "raw",
    });
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
    expect(result.error).toContain("Request aborted by user");
    // Nothing was read before the abort — zero-byte partial, abort cause.
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "aborted",
      capturedBytes: 0,
    });
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
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "curl-exit",
      capturedBytes: "partial".length,
      capturedBytesBasis: "decoded",
    });
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
    // Sandbox byte counts are honestly labeled: the decoded output's UTF-8
    // length, including every CRLF byte.
    expect(result.capture).toMatchObject({
      complete: true,
      stopReason: "end",
      capturedBytes: Buffer.byteLength("line1\r\nline2\r\n", "utf-8"),
      capturedBytesBasis: "decoded",
    });
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
        // Error after the first chunk is consumed, so the partial capture
        // is real (error() drops unread queued chunks).
        setTimeout(() => c.error(new Error("synthetic connection reset")), 10);
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
    // An ordinary stream failure is error, not a deadline timeout — the
    // bounded partial capture is preserved with its cause.
    expect(result.body).toContain("partial;");
    expect(result.body).toContain("INCOMPLETE");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "error",
      capturedBytes: "partial;".length,
      capturedBytesBasis: "raw",
    });
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
    expect(result.error).toContain("Request aborted by user");
    // Abort mid-body: the bounded partial capture is preserved.
    expect(result.body).toContain("<html>partial");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "aborted",
      capturedBytes: "<html>partial".length,
      capturedBytesBasis: "raw",
    });
    expect(cancelled).toBe(true);
  }, 5_000);

  it.each([
    "end",
    "byte-cap",
    "timeout",
  ])("preserves %s capture completeness when the response spill write fails", async (stopReason) => {
    const ctx = ctxWithScratchLogs();
    mkdirSync(ctx.session.logsPath, { recursive: true });
    writeFileSync(join(ctx.session.logsPath, "http-responses"), "occupied");
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          enc.encode(
            "x".repeat(stopReason === "byte-cap" ? 5 * 1024 * 1024 + 1 : 6_000),
          ),
        );
        if (stopReason !== "timeout") controller.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );
    const result = (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/spill-failure",
        method: "GET",
        followRedirects: false,
        timeout: stopReason === "timeout" ? 20 : 2_000,
        toolCallDescription: "Read a response whose spill write fails",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.capture).toMatchObject({
      complete: stopReason === "end",
      stopReason,
    });
    expect(result.success).toBe(stopReason === "end");
    expect(result.body.startsWith("x".repeat(5_000))).toBe(true);
    expect(result.body).toContain("failed to save");
    expect(result.body).not.toContain("response saved to");
    if (stopReason === "end") {
      expect(result.body).toContain("failed to save full response");
      expect(result.body).not.toContain("INCOMPLETE");
    } else {
      expect(result.body).toContain("INCOMPLETE");
      expect(result.body).toContain(
        stopReason === "byte-cap"
          ? "download capped at"
          : "Request timeout after",
      );
      expect(result.body).not.toContain("full response");
    }
  });

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
    // Complete transfer: an ordinary success with complete capture metadata.
    expect(large.capture).toMatchObject({
      complete: true,
      stopReason: "end",
      capturedBytes: 6_000,
      capturedBytesBasis: "raw",
    });
  });

  it("counts raw bytes exactly for CRLF and multibyte bodies", async () => {
    const body = "héllo\r\nwörld\r\n€\r\n";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "content-length": String(Buffer.byteLength(body, "utf-8")),
            },
          }),
      ),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/counts",
        method: "GET",
        followRedirects: false,
        timeout: 2_000,
        toolCallDescription: "CRLF + multibyte byte counts",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    // capturedBytes is the raw byte count: CRLF bytes and multibyte UTF-8
    // sequences counted exactly, not the character count.
    expect(result.capture).toMatchObject({
      complete: true,
      stopReason: "end",
      capturedBytes: Buffer.byteLength(body, "utf-8"),
      capturedBytesBasis: "raw",
      declaredBytes: Buffer.byteLength(body, "utf-8"),
    });
    expect(result.capture.capturedBytes).not.toBe(body.length);
  });

  it("keeps a complete 4xx as success (pre-existing local-path semantics)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("not found body", { status: 404 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/missing",
        method: "GET",
        followRedirects: false,
        timeout: 2_000,
        toolCallDescription: "complete 404",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    // Complete capture stays success:true — only incomplete transfers flip
    // it. The status itself is already a first-class field.
    expect(result.success).toBe(true);
    expect(result.status).toBe(404);
    expect(result.capture).toMatchObject({
      complete: true,
      stopReason: "end",
    });
  });

  it("labels an incomplete capture with advertised Content-Length, never as a denominator", async () => {
    // Endless body: hits the byte cap; note must say advertised, not "of".
    const chunk = new Uint8Array(64 * 1024).fill(65);
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        c.enqueue(chunk);
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-length": "999999999" },
          }),
      ),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/advertised",
        method: "GET",
        followRedirects: false,
        timeout: 30_000,
        toolCallDescription: "cap with advertised length",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.body).toContain("advertised Content-Length: 999999999");
    expect(result.body).not.toMatch(/captured \d+ of \d+/);
    expect(result.capture).toMatchObject({
      stopReason: "byte-cap",
      declaredBytes: 999_999_999,
    });
  }, 10_000);

  it("treats a zero-length chunk at the exact cap followed by EOF as complete", async () => {
    const CAP = 5 * 1024 * 1024;
    // [cap bytes, empty chunk, EOF]: an empty non-done chunk is not evidence
    // of more bytes — the body is complete.
    const full = new Uint8Array(CAP).fill(66); // "B" * cap
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(full);
        c.enqueue(new Uint8Array(0));
        c.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/exact-cap-empty-eof",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription:
          "GET whose cap lands exactly at EOF via an empty chunk",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    expect(result.capture).toMatchObject({
      complete: true,
      stopReason: "end",
      capturedBytes: CAP,
    });
    expect(result.body.startsWith("BBBB")).toBe(true);
  }, 10_000);

  it("treats multiple zero-length chunks at the exact cap as still live until EOF", async () => {
    const CAP = 5 * 1024 * 1024;
    // [cap, empty, empty, EOF]: every empty is skipped, completion decided
    // by the eventual EOF only.
    const full = new Uint8Array(CAP).fill(67); // "C" * cap
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(full);
        c.enqueue(new Uint8Array(0));
        c.enqueue(new Uint8Array(0));
        c.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/exact-cap-empties-eof",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET with empties before EOF at the cap",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    expect(result.capture).toMatchObject({
      complete: true,
      stopReason: "end",
    });
  }, 10_000);

  it("a nonempty chunk after empties at the exact cap is a byte-cap overflow", async () => {
    const CAP = 5 * 1024 * 1024;
    // [cap, empty, nonempty]: the empty is skipped; the nonempty chunk proves
    // the body exceeded the cap.
    const full = new Uint8Array(CAP).fill(68); // "D" * cap
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(full);
        c.enqueue(new Uint8Array(0));
        c.enqueue(new Uint8Array([88])); // "X"
        c.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/exact-cap-empty-overflow",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET whose empties precede real overflow",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "byte-cap",
      capturedBytes: CAP,
    });
    expect(result.body).toContain("INCOMPLETE");
  }, 10_000);

  it("a stalled peek at the exact cap dies by the deadline, not as overflow", async () => {
    const CAP = 5 * 1024 * 1024;
    // [cap, stall forever]: the next chunk never arrives and never EOfs —
    // the deadline must classify the outcome, never a hang.
    const full = new Uint8Array(CAP).fill(69); // "E" * cap
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(full);
        // then stall — no further enqueue, no close
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/exact-cap-stall",
        method: "GET",
        followRedirects: false,
        timeout: 100,
        toolCallDescription: "GET stalling at the exact cap",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Request timeout after 100ms");
    expect(result.capture.stopReason).toBe("timeout");
  }, 5_000);

  it("a user abort during the stalled peek reports aborted, not overflow", async () => {
    const CAP = 5 * 1024 * 1024;
    const full = new Uint8Array(CAP).fill(70); // "F" * cap
    const ac = new AbortController();
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(full);
        setTimeout(() => ac.abort(), 50);
        // then stall
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
        url: "https://example.com/exact-cap-abort",
        method: "GET",
        followRedirects: false,
        timeout: 30_000,
        toolCallDescription: "GET aborted at the stalled cap boundary",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Request aborted by user");
    expect(result.capture.stopReason).toBe("aborted");
  }, 5_000);

  // --- First terminal outcome vs a same-turn abort (settlement ordering) ---
  // HWM-0 pull fixtures: each pull serves a PENDING read, so the second pull
  // fires the terminal event and the host abort in one turn — whichever
  // settles first is the truthful outcome.

  it("an EOF that settles before a same-turn abort stays complete", async () => {
    const enc = new TextEncoder();
    const ac = new AbortController();
    let reads = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          if (reads++ === 0) {
            c.enqueue(enc.encode("part-1;"));
            return;
          }
          c.close(); // settles FIRST
          ac.abort(); // same turn, second — must not overwrite the EOF
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/eof-then-abort",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET whose EOF beats a same-turn abort",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(true);
    expect(result.body).toBe("part-1;");
    expect(result.capture).toMatchObject({
      complete: true,
      stopReason: "end",
    });
  }, 5_000);

  it("an abort that settles before the stream ends stays incomplete", async () => {
    const enc = new TextEncoder();
    const ac = new AbortController();
    let reads = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          if (reads++ === 0) {
            c.enqueue(enc.encode("part-1;"));
            return;
          }
          // No close: the abort's reader.cancel() provides the stream end,
          // and the abort settled first — the capture is incomplete.
          ac.abort();
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/abort-first",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET whose same-turn abort beats the end",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Request aborted by user");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "aborted",
    });
    // Bytes that settled before the abort remain captured evidence.
    expect(result.body).toContain("part-1;");
  }, 5_000);

  it("a byte-cap outcome survives an abort racing the cap cancellation", async () => {
    const CAP = 5 * 1024 * 1024;
    const chunk = new Uint8Array(64 * 1024).fill(65); // "A" * 64KiB
    const ac = new AbortController();
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          c.enqueue(chunk);
        },
        cancel() {
          // truncatedAtCap cancels the reader AFTER assigning byte-cap; the
          // abort firing here must not overwrite the cap outcome.
          ac.abort();
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/cap-then-abort",
        method: "GET",
        followRedirects: false,
        timeout: 30_000,
        toolCallDescription: "GET capped before a racing abort",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("capped");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "byte-cap",
      capturedBytes: CAP,
    });
  }, 10_000);

  it("a stream error retains its outcome when the signal aborts in the same turn", async () => {
    const enc = new TextEncoder();
    const ac = new AbortController();
    let reads = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          if (reads++ === 0) {
            c.enqueue(enc.encode("part-1;"));
            return;
          }
          c.error(new TypeError("synthetic connection reset")); // settles FIRST
          ac.abort(); // must not overwrite the error
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/error-then-abort",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET whose stream error beats the abort",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("synthetic connection reset");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "error",
    });
  }, 5_000);

  it("an abort settling before a same-turn stream error stays aborted", async () => {
    const enc = new TextEncoder();
    const ac = new AbortController();
    let reads = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          if (reads++ === 0) {
            c.enqueue(enc.encode("part-1;"));
            return;
          }
          ac.abort(); // settles FIRST
          c.error(new TypeError("synthetic connection reset"));
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/abort-then-error",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET whose abort beats a same-turn error",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Request aborted by user");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "aborted",
    });
  }, 5_000);

  // --- Abort classification is identity-based, not name-based ---

  it("an unrelated AbortError without a host abort stays an error", async () => {
    const enc = new TextEncoder();
    let reads = 0;
    // An AbortError-shaped error that is NOT this signal's reason — e.g. an
    // adapter-internal cancellation — must not be relabeled as our abort.
    const unrelated = new Error("adapter-internal cancellation");
    unrelated.name = "AbortError";
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          if (reads++ === 0) {
            c.enqueue(enc.encode("part-1;"));
            return;
          }
          c.error(unrelated);
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/unrelated-abort-error",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET with an unrelated AbortError",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("adapter-internal cancellation");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "error",
    });
  }, 5_000);

  it("an unrelated AbortError stays an error even when the host aborts later", async () => {
    const enc = new TextEncoder();
    const ac = new AbortController();
    let reads = 0;
    const unrelated = new Error("adapter-internal cancellation");
    unrelated.name = "AbortError";
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          if (reads++ === 0) {
            c.enqueue(enc.encode("part-1;"));
            return;
          }
          c.error(unrelated); // settles FIRST
          ac.abort(); // a later host abort must not relabel the cause
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(
      ctxWithScratchLogs({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/unrelated-abort-then-host-abort",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription:
          "GET with an unrelated AbortError before a host abort",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("adapter-internal cancellation");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "error",
    });
  }, 5_000);

  // Real fetch against a local loopback server: the native abort machinery
  // rejects the body with the signal's own reason object — classification
  // must match by identity. The barrier is a spy on the NATIVE body reader's
  // read(): the first read captures the 19-byte prefix, the second read
  // invocation fires the abort mid-consumption and returns the original
  // pending native read. The Response, its body, and reader.closed stay
  // untouched — no transform substitute.
  const NATIVE_PREFIX = "streaming-body-start"; // 20 bytes

  async function runNativeAbortCase(reason: undefined | Error) {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write(NATIVE_PREFIX);
      // Keep the connection open — only the abort ends this read.
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const port = (server.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/endless`;
    const ac = new AbortController();

    try {
      // Truly-native fetch: clear any prior stubs BEFORE capturing.
      vi.unstubAllGlobals();
      const realFetch = globalThis.fetch;
      let readCalls = 0;
      vi.stubGlobal(
        "fetch",
        vi.fn(async (...args: Parameters<typeof realFetch>) => {
          const res = await realFetch(...args);
          if (res.body === null) throw new Error("native body missing");
          const body = res.body;
          const origGetReader = body.getReader.bind(body);
          Object.defineProperty(body, "getReader", {
            value: () => {
              const reader = origGetReader();
              const origRead = reader.read.bind(reader);
              Object.defineProperty(reader, "read", {
                value: () => {
                  readCalls++;
                  const pending = origRead();
                  if (readCalls === 2) {
                    // The prefix is already captured by the first read —
                    // abort mid-consumption, handing back the native pending
                    // read.
                    ac.abort(reason);
                  }
                  return pending;
                },
              });
              return reader;
            },
          });
          return res;
        }),
      );

      const base = makeCtx();
      const ctx = ctxWithScratchLogs({
        abortSignal: ac.signal,
        target: url,
        session: {
          ...base.session,
          targets: [url],
        } as SessionInfo,
      });
      const result = (await httpRequest(ctx).execute?.(
        {
          url,
          method: "GET",
          followRedirects: false,
          timeout: 30_000,
          toolCallDescription: "GET cancelled natively mid-body",
        },
        { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
      )) as HttpRequestResult;

      return { result, readCalls };
    } finally {
      // Bounded teardown: force the abort (a regression may exit before the
      // read barrier fires), destroy any still-open connection, then await
      // the server's close before unstubbing.
      ac.abort();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      vi.unstubAllGlobals();
    }
  }

  it("a native fetch cancellation with the default reason is classified aborted mid-body", async () => {
    const { result, readCalls } = await runNativeAbortCase(undefined);

    // The abort fired on the second native read — after the prefix was
    // captured, during body consumption (never before headers).
    expect(readCalls).toBeGreaterThanOrEqual(2);
    expect(result.success).toBe(false);
    expect(result.status).toBe(200);
    expect(result.error).toContain("Request aborted by user");
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "aborted",
    });
    expect(result.body).toContain(NATIVE_PREFIX);
    expect(result.capture.capturedBytes).toBe(NATIVE_PREFIX.length);
  }, 15_000);

  it("a native fetch cancellation with a custom reason object is classified aborted by identity", async () => {
    const { result, readCalls } = await runNativeAbortCase(
      new Error("host cancelled"),
    );

    expect(readCalls).toBeGreaterThanOrEqual(2);
    expect(result.success).toBe(false);
    expect(result.status).toBe(200);
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "aborted",
    });
    expect(result.body).toContain(NATIVE_PREFIX);
    expect(result.capture.capturedBytes).toBe(NATIVE_PREFIX.length);
  }, 15_000);

  it("an unexpected processing failure propagates instead of hanging or faking EOF", async () => {
    const enc = new TextEncoder();
    let reads = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          if (reads++ === 0) {
            c.enqueue(enc.encode("part-1;"));
            return;
          }
          c.enqueue({
            byteLength: 4,
            subarray: undefined,
          } as unknown as Uint8Array);
        },
        cancel() {
          cancelled = true;
        },
      },
      { highWaterMark: 0 },
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 200 })),
    );

    const result = (await httpRequest(ctxWithScratchLogs()).execute?.(
      {
        url: "https://example.com/processing-failure",
        method: "GET",
        followRedirects: false,
        timeout: 5_000,
        toolCallDescription: "GET whose chunk processing fails",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("subarray");
    expect(result.capture.stopReason).toBe("error");
    // The open stream was actually cancelled, not merely lock-released.
    expect(cancelled).toBe(true);
  }, 5_000);

  // --- Windows sandbox boundary (mocked helper contract; runs on all OS) ---

  type SandboxExecuteCall = {
    command: string;
    opts?: { timeout?: number; envVars?: Record<string, string>; cwd?: string };
  };

  function windowsSandboxMock(
    respond: (call: SandboxExecuteCall) => {
      stdout: string;
      stderr?: string;
      exitCode: number;
      success: boolean;
    },
  ): { execute: ReturnType<typeof vi.fn>; calls: SandboxExecuteCall[] } {
    const calls: SandboxExecuteCall[] = [];
    const execute = vi.fn(async (command: string, opts?: unknown) => {
      const call = { command, opts: opts as SandboxExecuteCall["opts"] };
      calls.push(call);
      const r = respond(call);
      return {
        success: r.success,
        exitCode: r.exitCode,
        stdout: r.stdout,
        stderr: r.stderr ?? "",
      };
    });
    return { execute, calls };
  }

  const windowsCtx = (execute: ReturnType<typeof vi.fn>): ToolContext =>
    ctxWithScratchLogs({
      sandbox: {
        type: "windows",
        execute,
      } as unknown as ToolContext["sandbox"],
    });

  const callWindowsTool = async (
    ctx: ToolContext,
    input: {
      method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD";
      body?: string;
    },
  ): Promise<HttpRequestResult> =>
    (await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        followRedirects: false,
        timeout: 1_000,
        toolCallDescription: "Windows sandbox boundary",
        ...input,
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as HttpRequestResult;

  it("windows sandbox: complete GET runs the helper command with env, one execute call", async () => {
    const { execute, calls } = windowsSandboxMock((call) => {
      const marker = call.opts?.envVars?.APEX_HTTP_MARKER ?? "";
      return {
        success: true,
        exitCode: 0,
        stdout: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok-body\n${marker}0\n`,
      };
    });
    const result = await callWindowsTool(windowsCtx(execute), {
      method: "GET",
    });

    expect(result.success).toBe(true);
    expect(result.body).toBe("ok-body");
    expect(result.capture).toMatchObject({
      complete: true,
      stopReason: "end",
    });
    // Exactly one dispatch: no POSIX printf staging, no rm cleanup.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.command).toContain("powershell.exe");
    // Request data travels in envVars, including resolved headers in argv.
    const env = calls[0]?.opts?.envVars ?? {};
    expect(env.APEX_HTTP_CURL_ARGS).toContain("-X");
    expect(env.APEX_HTTP_CURL_ARGS).toContain("GET");
    expect(env.APEX_HTTP_CURL_ARGS).toContain("https://example.com/api");
    expect(Number(env.APEX_HTTP_MAX_BYTES)).toBe(5 * 1024 * 1024);
    expect(env.APEX_HTTP_MARKER).toMatch(/^__APEX_[0-9a-f]+_CURL_EXIT_$/);
    // Chunked body contract: count/length always set, both 0 with no body.
    expect(env.APEX_HTTP_BODY_COUNT).toBe("0");
    expect(env.APEX_HTTP_BODY_LENGTH).toBe("0");
    expect(env.APEX_HTTP_BODY_0).toBeUndefined();
    expect(env.APEX_HTTP_BODY).toBeUndefined();
  });

  it("windows sandbox: POST forwards the body as base64 env with no POSIX setup or cleanup", async () => {
    const { execute, calls } = windowsSandboxMock((call) => {
      const marker = call.opts?.envVars?.APEX_HTTP_MARKER ?? "";
      return {
        success: true,
        exitCode: 0,
        stdout: `HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\ncreated\n${marker}0\n`,
      };
    });
    const result = await callWindowsTool(windowsCtx(execute), {
      method: "POST",
      body: "hello=windows",
    });

    expect(result.success).toBe(true);
    expect(result.status).toBe(201);
    expect(calls).toHaveLength(1);
    // No /tmp staging write and no rm cleanup were dispatched.
    expect(calls[0]?.command).not.toContain("/tmp");
    expect(calls.join(" ")).not.toContain("rm -f");
    // The body rides as chunked base64 env (small body: one chunk) for the
    // helper's own temp-file staging; the legacy single var is gone.
    const env = calls[0]?.opts?.envVars ?? {};
    const encoded = Buffer.from("hello=windows", "utf8").toString("base64");
    expect(env.APEX_HTTP_BODY_COUNT).toBe("1");
    expect(env.APEX_HTTP_BODY_LENGTH).toBe(String(encoded.length));
    expect(env.APEX_HTTP_BODY_0).toBe(encoded);
    expect(env.APEX_HTTP_BODY_1).toBeUndefined();
    expect(env.APEX_HTTP_BODY).toBeUndefined();
  });

  it("windows sandbox: marker-less output is classified as a cap", async () => {
    const { execute } = windowsSandboxMock(() => ({
      success: true,
      exitCode: 0,
      stdout:
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial-until-cap",
    }));
    const result = await callWindowsTool(windowsCtx(execute), {
      method: "GET",
    });

    expect(result.success).toBe(false);
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "byte-cap",
    });
    expect(result.body).toContain("INCOMPLETE");
  });

  it("windows sandbox: nonzero helper exit surfaces redacted stderr alongside the partial response", async () => {
    const { execute } = windowsSandboxMock(() => ({
      success: false,
      exitCode: 2,
      stdout:
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial-before-failure",
      stderr: "powershell wrapper failed mid-transfer",
    }));
    const result = await callWindowsTool(windowsCtx(execute), {
      method: "GET",
    });

    expect(result.success).toBe(false);
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "sandbox-exec",
    });
    // Native helper stderr is surfaced in the failure diagnostics, not suppressed.
    expect(result.error).toContain("powershell wrapper failed mid-transfer");
    expect(result.body).toContain("partial-before-failure");
  });

  it("windows sandbox: curl nonzero with a partial 200 stays incomplete", async () => {
    const { execute } = windowsSandboxMock((call) => {
      const marker = call.opts?.envVars?.APEX_HTTP_MARKER ?? "";
      return {
        success: true,
        exitCode: 0,
        stdout: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial-download\n${marker}28\n`,
      };
    });
    const result = await callWindowsTool(windowsCtx(execute), {
      method: "GET",
    });

    expect(result.success).toBe(false);
    expect(result.status).toBe(200);
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "curl-exit",
    });
    expect(result.body).toContain("partial-download");
    expect(result.body).toContain("INCOMPLETE");
  });

  it("windows sandbox: execute timeout includes PowerShell startup and cleanup headroom", async () => {
    const { execute, calls } = windowsSandboxMock((call) => {
      const marker = call.opts?.envVars?.APEX_HTTP_MARKER ?? "";
      return {
        success: true,
        exitCode: 0,
        stdout: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok\n${marker}0\n`,
      };
    });
    // 40s deadline: +10s Windows headroom must show past the 30s floor.
    await httpRequest(windowsCtx(execute)).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 40_000,
        toolCallDescription: "Windows timeout headroom",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    expect(calls.at(-1)?.opts?.timeout).toBe(55);
  });

  it("windows sandbox: a negative curl exit marker is curl-exit, not byte-cap", async () => {
    const { execute } = windowsSandboxMock((call) => {
      const marker = call.opts?.envVars?.APEX_HTTP_MARKER ?? "";
      return {
        success: true,
        exitCode: 0,
        stdout: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nterminated-output\n${marker}-1073741519\n`,
      };
    });
    const result = await callWindowsTool(windowsCtx(execute), {
      method: "GET",
    });

    expect(result.success).toBe(false);
    expect(result.capture).toMatchObject({
      complete: false,
      stopReason: "curl-exit",
    });
    expect(result.error).toContain("-1073741519");
  });

  it("windows sandbox: curl-exit failures surface native curl stderr diagnostics", async () => {
    const { execute } = windowsSandboxMock((call) => {
      const marker = call.opts?.envVars?.APEX_HTTP_MARKER ?? "";
      return {
        success: true,
        exitCode: 0,
        stdout: `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial\n${marker}28\n`,
        stderr: "curl: (28) Operation timed out",
      };
    });
    const result = await callWindowsTool(windowsCtx(execute), {
      method: "GET",
    });

    expect(result.success).toBe(false);
    expect(result.capture).toMatchObject({ stopReason: "curl-exit" });
    // --show-error diagnostics ride stderr — surfaced, not suppressed.
    expect(result.error).toContain("curl: (28) Operation timed out");
  });

  it("linux sandbox: execute timeout keeps the existing floor (no Windows headroom)", async () => {
    const calls: { opts?: { timeout?: number } }[] = [];
    const execute = vi.fn(async (_command: string, opts?: unknown) => {
      calls.push({ opts: opts as { timeout?: number } });
      return {
        success: true,
        exitCode: 0,
        stdout: "HTTP/1.1 200 OK\n\n",
        stderr: "",
      };
    });
    const ctx = ctxWithScratchLogs({
      sandbox: { type: "linux", execute } as unknown as ToolContext["sandbox"],
    });
    await httpRequest(ctx).execute?.(
      {
        url: "https://example.com/api",
        method: "GET",
        followRedirects: false,
        timeout: 40_000,
        toolCallDescription: "Linux timeout floor",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );

    expect(calls.at(-1)?.opts?.timeout).toBe(40);
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import { type GetPageResponse, getPage } from "./getPage";
import type { ToolContext } from "./types";

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

// Full-lifetime liveness: the 30s deadline must cover the body read, not just
// the headers, and the body must be byte-bounded while streaming. All fixtures
// are synthetic streams — no network.
describe("getPage body liveness", () => {
  const enc = new TextEncoder();

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  function stalledBodyStream(first: string): ReadableStream<Uint8Array> {
    return new ReadableStream({
      start(c) {
        c.enqueue(enc.encode(first));
        // Never enqueues again and never closes — a stalling body.
      },
    });
  }

  it("fails with a bounded timeout when the body stalls after headers arrive", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(stalledBodyStream("<html><body>partial"), {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const pending = getPage(makeCtx()).execute?.(
      { url: "https://example.com/stall", toolCallDescription: "Stalled page" },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    );
    await vi.advanceTimersByTimeAsync(30_000);
    const result = (await pending) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Request timeout after 30s");
    // Timeout after partial data: the bounded partial extraction survives,
    // marked incomplete — never discarded, never a clean success.
    expect(result.content).toContain("partial");
    expect(result.content).toContain("INCOMPLETE");
    expect(result.contentTruncated).toBe(true);
    expect(result.stopReason).toBe("timeout");
  }, 5_000);

  it("bounds an endless body at the byte cap and cancels the stream", async () => {
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
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/plain" },
          }),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      {
        url: "https://example.com/endless",
        toolCallDescription: "Endless page",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    // A capped capture is not an ordinary success — the producer stop reason
    // is preserved, not overwritten by the preview-limit cause.
    expect(result.stopReason).toBe("byte-cap");
    expect(result.contentTruncated).toBe(true);
    // Streaming cap: the tool stopped reading instead of buffering forever
    // (response.text() would never finish on this fixture).
    expect(delivered).toBeLessThanOrEqual(CAP + 4 * chunk.byteLength);
    expect(cancelled).toBe(true);
    // Content is bounded to the inline limit, and both truncations are
    // reported: the 50k preview cut and the INCOMPLETE capture.
    expect((result.content ?? "").length).toBeLessThanOrEqual(50_000 + 400);
    expect(result.content).toContain("content truncated");
    expect(result.content).toContain("INCOMPLETE");
  }, 10_000);

  it("reports failure when the body stream errors mid-read", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode("<html><body>partial page"));
        // Error after the first chunk is consumed, so the partial capture
        // is real (error() drops unread queued chunks).
        setTimeout(() => c.error(new Error("synthetic connection reset")), 10);
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      { url: "https://example.com/broken", toolCallDescription: "Broken page" },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.error).toContain("synthetic connection reset");
    // An ordinary stream failure is labeled error, not a deadline timeout.
    expect(result.stopReason).toBe("error");
    expect(result.content).toContain("partial page");
    expect(result.content).toContain("INCOMPLETE");
    expect(result.contentTruncated).toBe(true);
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
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = (await getPage(
      makeCtx({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/slow",
        toolCallDescription: "Page aborted by the host mid-body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Request aborted by user");
    expect(result.stopReason).toBe("aborted");
    expect(result.content).toContain("partial");
    expect(result.content).toContain("INCOMPLETE");
    expect(cancelled).toBe(true);
  }, 5_000);

  it("cancels the unread body on a non-OK response", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode("<html>not found"));
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(body, {
            status: 404,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      { url: "https://example.com/missing", toolCallDescription: "404 page" },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.error).toContain("404");
    expect(cancelled).toBe(true);
  });

  it("cancels the unread body on an unsupported content type", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode("binary-bytes"));
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "application/octet-stream" },
          }),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      {
        url: "https://example.com/binary",
        toolCallDescription: "Binary download",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Unsupported content type");
    expect(cancelled).toBe(true);
  });

  it("caps a body delivered as many tiny chunks plus one huge chunk", async () => {
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
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/plain" },
          }),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      {
        url: "https://example.com/adversarial",
        toolCallDescription: "Adversarially chunked page",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.stopReason).toBe("byte-cap");
    expect(cancelled).toBe(true);
    // Content is bounded to the inline limit with honest truncation notes;
    // the leading text proves every tiny chunk landed before the huge one.
    expect(result.content?.startsWith("A".repeat(tinyCount))).toBe(true);
    expect(result.content).toContain("content truncated");
    expect(result.content).toContain("INCOMPLETE");
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
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/plain" },
          }),
      ),
    );

    const started = Date.now();
    const result = (await getPage(makeCtx()).execute?.(
      {
        url: "https://example.com/hanging-cancel",
        toolCallDescription: "Page whose stream cancel never settles",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.stopReason).toBe("byte-cap");
    expect(cancelCalled).toBe(true);
    expect(Date.now() - started).toBeLessThan(2_000);
  }, 5_000);

  it("aborts promptly when the host aborts between headers and body registration", async () => {
    const ac = new AbortController();
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(enc.encode("<html>partial"));
        // Never completes on its own.
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const res = new Response(body, {
          status: 200,
          headers: { "content-type": "text/html" },
        });
        ac.abort(); // after headers exist, before the body reader registers
        return res;
      }),
    );

    const result = (await getPage(
      makeCtx({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/pre-aborted",
        toolCallDescription: "Page pre-aborted between headers and body",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Request aborted by user");
    expect(result.stopReason).toBe("aborted");
    expect(cancelled).toBe(true);
  }, 5_000);

  it("extracts title and content from a healthy page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            "<html><head><title>Example</title></head><body><p>hello page</p></body></html>",
            { status: 200, headers: { "content-type": "text/html" } },
          ),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      {
        url: "https://example.com/ok",
        toolCallDescription: "Healthy page",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(true);
    expect(result.title).toBe("Example");
    expect(result.content).toContain("hello page");
    expect(result.contentTruncated).toBeUndefined();
    expect(result.stopReason).toBeUndefined();
  });
});

// Capture-vs-preview distinction: a >50k extraction followed by a producer
// failure must be a FAILED capture with the producer stop reason — the 50k
// preview cut never launders an incomplete download into success.
describe("getPage preview-limit vs producer failure", () => {
  const enc = new TextEncoder();
  const BIG_BODY = `<html><body>${"page text ".repeat(10_000)}</body></html>`; // >50k chars

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it(">50k then stream error: success=false, stopReason=error (not content-limit)", async () => {
    const body = new ReadableStream({
      start(c) {
        c.enqueue(enc.encode(BIG_BODY));
        setTimeout(() => c.error(new Error("synthetic connection reset")), 10);
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      {
        url: "https://example.com/big-broken",
        toolCallDescription: "big + error",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.stopReason).toBe("error");
    expect(result.contentTruncated).toBe(true);
    // Both facts visible: the preview cut AND the incomplete capture.
    expect(result.content).toContain("content truncated");
    expect(result.content).toContain("INCOMPLETE");
    expect((result.content ?? "").length).toBeLessThanOrEqual(50_000 + 400);
  });

  it(">50k then byte-cap: success=false, stopReason=byte-cap", async () => {
    const CAP = 5 * 1024 * 1024;
    const chunk = new Uint8Array(64 * 1024).fill(97);
    const body = new ReadableStream({
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
            headers: { "content-type": "text/plain" },
          }),
      ),
    );
    expect(CAP).toBeGreaterThan(0); // fixture sanity

    const result = (await getPage(makeCtx()).execute?.(
      {
        url: "https://example.com/big-capped",
        toolCallDescription: "big + cap",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.stopReason).toBe("byte-cap");
    expect(result.contentTruncated).toBe(true);
    expect(result.content).toContain("content truncated");
    expect(result.content).toContain("INCOMPLETE");
  }, 10_000);

  it(">50k then host abort: success=false, stopReason=aborted", async () => {
    const ac = new AbortController();
    const body = new ReadableStream({
      start(c) {
        c.enqueue(enc.encode(BIG_BODY));
        setTimeout(() => ac.abort(), 50);
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = (await getPage(
      makeCtx({ abortSignal: ac.signal }),
    ).execute?.(
      {
        url: "https://example.com/big-abort",
        toolCallDescription: "big + abort",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: ac.signal },
    )) as GetPageResponse;

    expect(result.success).toBe(false);
    expect(result.stopReason).toBe("aborted");
    expect(result.content).toContain("content truncated");
    expect(result.content).toContain("INCOMPLETE");
  }, 5_000);

  it(">50k at clean EOF: success=true with content-limit stopReason only", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(BIG_BODY, {
            status: 200,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = (await getPage(makeCtx()).execute?.(
      { url: "https://example.com/big-ok", toolCallDescription: "big + EOF" },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as GetPageResponse;

    // Complete capture, preview-limited — this IS a success.
    expect(result.success).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.stopReason).toBe("content-limit");
    expect(result.contentTruncated).toBe(true);
    expect(result.content).toContain("content truncated");
    expect(result.content).not.toContain("INCOMPLETE");
  });
});

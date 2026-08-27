// O6 — flush and shutdown hardening. The runtime's shutdown is idempotent
// and bounded; forceFlush precedes processor teardown; in-flight root spans
// end before the flush; signals and fatal errors exit through the bounded
// shutdown; a hung exporter cannot block process exit; embedded hosts are
// never touched; the final trace reaches a local OTLP receiver.

import { createServer, type Server } from "node:http";
import type {
  ReadableSpan,
  Span as SdkSpan,
  SpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import {
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getApexTracer } from "../observability";
import {
  installObservabilityExitHandlers,
  resetObservabilityRuntime,
  startObservabilityRuntime,
} from "./runtime";

const OTEL_VARS = [
  "OTEL_SDK_DISABLED",
  "OTEL_SERVICE_NAME",
  "OTEL_RESOURCE_ATTRIBUTES",
  "OTEL_EXPORTER_OTLP_ENDPOINT",
  "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
  "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
];
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of OTEL_VARS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(async () => {
  await resetObservabilityRuntime();
  for (const key of OTEL_VARS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

/** Span processor that records lifecycle call order. */
class RecordingProcessor implements SpanProcessor {
  readonly calls: string[] = [];
  private readonly inner: SpanProcessor;
  constructor(inner: SpanProcessor) {
    this.inner = inner;
  }
  onStart(span: SdkSpan): void {
    this.inner.onStart(span, {} as never);
  }
  onEnd(span: ReadableSpan): void {
    this.calls.push("onEnd");
    this.inner.onEnd(span);
  }
  async shutdown(): Promise<void> {
    this.calls.push("shutdown");
    await this.inner.shutdown();
  }
  async forceFlush(): Promise<void> {
    this.calls.push("forceFlush");
    await this.inner.forceFlush();
  }
}

/** Processor whose shutdown never settles. */
class HungProcessor implements SpanProcessor {
  onStart(_span: SdkSpan): void {}
  onEnd(_span: ReadableSpan): void {}
  async forceFlush(): Promise<void> {}
  async shutdown(): Promise<void> {
    await new Promise<void>(() => {});
  }
}

function startWithProcessors(
  processors: SpanProcessor[],
  shutdownTimeoutMs?: number,
) {
  process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT =
    "http://127.0.0.1:4318/v1/traces";
  return startObservabilityRuntime(process.env, {
    ...(processors.length > 0 ? { spanProcessors: processors } : {}),
    ...(shutdownTimeoutMs !== undefined ? { shutdownTimeoutMs } : {}),
  });
}

// ---------------------------------------------------------------------------
// Shutdown semantics
// ---------------------------------------------------------------------------

describe("shutdown semantics", () => {
  it("forceFlush() runs before shutdown()", async () => {
    const exporter = new InMemorySpanExporter();
    const recorder = new RecordingProcessor(new SimpleSpanProcessor(exporter));
    const runtime = startWithProcessors([recorder]);

    getApexTracer().startSpan("s").end();
    // The runtime's shutdown ends root spans then flushes THEN tears down;
    // read the exporter before teardown clears it (InMemorySpanExporter
    // semantics) — via an explicit forceFlush first.
    await runtime.forceFlush();
    expect(exporter.getFinishedSpans()).toHaveLength(1);

    await runtime.shutdown();
    expect(recorder.calls).toEqual([
      "onEnd",
      "forceFlush",
      "forceFlush",
      "shutdown",
    ]);
  });

  it("repeated shutdown calls execute the real shutdown once", async () => {
    const exporter = new InMemorySpanExporter();
    const recorder = new RecordingProcessor(new SimpleSpanProcessor(exporter));
    const runtime = startWithProcessors([recorder]);

    await Promise.all([runtime.shutdown(), runtime.shutdown()]);
    await runtime.shutdown();

    expect(recorder.calls.filter((c) => c === "shutdown")).toHaveLength(1);
  });

  it("a hung exporter cannot block process exit forever", async () => {
    const runtime = startWithProcessors([new HungProcessor()], 50);

    const started = Date.now();
    await expect(runtime.shutdown()).resolves.toBe("timed-out");
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("ends in-flight root spans before flushing", async () => {
    const exporter = new InMemorySpanExporter();
    const recorder = new RecordingProcessor(new SimpleSpanProcessor(exporter));
    const runtime = startWithProcessors([recorder]);

    // A root run still in flight at shutdown time.
    const rootSpan = getApexTracer().startSpan("invoke_agent default");
    const { registerActiveRootSpan } = await import("../observability");
    registerActiveRootSpan(rootSpan);

    await runtime.shutdown();

    // The registry ended the span BEFORE the flush: onEnd (the span ending)
    // precedes forceFlush in the recorded call order, so the span exported
    // with the final flush instead of leaking.
    expect(recorder.calls).toEqual(["onEnd", "forceFlush", "shutdown"]);
    expect((rootSpan as unknown as { ended: boolean }).ended).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Exit handlers
// ---------------------------------------------------------------------------

describe("installObservabilityExitHandlers", () => {
  const realExit = process.exit;
  const exitCalls: number[] = [];
  const cleanups: string[] = [];
  const errors: unknown[] = [];

  beforeEach(() => {
    exitCalls.length = 0;
    cleanups.length = 0;
    errors.length = 0;
    process.exit = ((code?: number) => {
      exitCalls.push(code ?? 0);
      throw new Error("__test_exit__");
    }) as typeof process.exit;
  });

  afterEach(() => {
    process.exit = realExit;
    // Remove every listener the install added.
    process.removeAllListeners("SIGINT");
    process.removeAllListeners("SIGTERM");
    process.removeAllListeners("uncaughtException");
    process.removeAllListeners("unhandledRejection");
  });

  function install(runtime: ReturnType<typeof startWithProcessors>) {
    return installObservabilityExitHandlers(runtime, {
      cleanup: (code) => cleanups.push(`cleanup:${code}`),
      onError: (error) => errors.push(error),
    });
  }

  it("signals trigger bounded shutdown then exit with the signal code", async () => {
    const runtime = startWithProcessors([new HungProcessor()], 50);
    install(runtime);

    process.emit("SIGINT", "SIGINT");
    // Cleanup ran synchronously; exit waits for the bounded shutdown.
    expect(cleanups).toEqual(["cleanup:130"]);
    expect(exitCalls).toHaveLength(0);

    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(exitCalls).toEqual([130]);
  });

  it("fatal errors are preserved after flushing (reported, exit code 1)", async () => {
    const runtime = startWithProcessors([new HungProcessor()], 50);
    install(runtime);

    const boom = new Error("fatal boom");
    process.emit("uncaughtException", boom);
    expect(errors).toEqual([boom]);

    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(exitCalls).toEqual([1]);
  });

  it("the first fatal wins — no double exit", async () => {
    const runtime = startWithProcessors([new HungProcessor()], 50);
    install(runtime);

    process.emit("uncaughtException", new Error("first"));
    process.emit("unhandledRejection", new Error("second"));

    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(errors).toHaveLength(1);
    expect(exitCalls).toEqual([1]);
  });

  it("a fatal error upgrades an in-flight normal exit without double teardown", async () => {
    const runtime = startWithProcessors([new HungProcessor()], 50);
    const exitWith = install(runtime);

    void exitWith(0);
    process.emit("uncaughtException", new Error("late failure"));

    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(cleanups).toEqual(["cleanup:0"]);
    expect(errors).toHaveLength(1);
    expect(exitCalls).toEqual([1]);
  });

  it("embedded mode (no runtime) never shuts down the host SDK", async () => {
    // The host (Console) registered its own SDK…
    const { startOtelTestHarness } = await import("./testkit");
    const hostOtel = startOtelTestHarness();
    try {
      // …Apex starts unconfigured → no-op runtime that touches nothing.
      const noopRuntime = startObservabilityRuntime({});
      install(noopRuntime);

      // A "host" span keeps recording across the exit path.
      const hostSpan = getApexTracer().startSpan("host-work");
      hostSpan.end();

      process.emit("SIGTERM", "SIGTERM");
      await new Promise((resolve) => setTimeout(resolve, 30));

      expect(exitCalls).toEqual([143]);
      // The host provider still works: the span recorded and ended.
      expect((hostSpan as unknown as { ended: boolean }).ended).toBe(true);
      expect(hostOtel.getFinishedSpans().map((s) => s.name)).toContain(
        "host-work",
      );
    } finally {
      await hostOtel.shutdown();
    }
  });
});

// ---------------------------------------------------------------------------
// End-to-end: the final trace reaches a local OTLP receiver
// ---------------------------------------------------------------------------

describe("final export", () => {
  async function startReceiver(): Promise<{
    server: Server;
    port: number;
    waitForRequests(count: number): Promise<Array<Record<string, unknown>>>;
  }> {
    const bodies: Array<Record<string, unknown>> = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        bodies.push(JSON.parse(Buffer.concat(chunks).toString("utf-8")));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end("{}");
      });
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("no port");
    }
    const waitForRequests = (count: number) =>
      new Promise<Array<Record<string, unknown>>>((resolve, reject) => {
        const started = Date.now();
        const poll = () => {
          if (bodies.length >= count) return resolve(bodies);
          if (Date.now() - started > 5000)
            return reject(new Error("receiver timed out"));
          setTimeout(poll, 20);
        };
        poll();
      });
    return { server, port: address.port, waitForRequests };
  }

  it("a complete root/model/subagent trace exports before completion", async () => {
    const receiver = await startReceiver();
    try {
      process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = `http://127.0.0.1:${receiver.port}/v1/traces`;
      const runtime = startObservabilityRuntime();

      await getApexTracer().startActiveSpan(
        "invoke_agent default",
        {
          attributes: {
            "gen_ai.operation.name": "invoke_agent",
            "pensar.run.id": "run_final",
          },
        },
        async (root) => {
          const model = getApexTracer().startSpan("ai.streamText");
          const sub = getApexTracer().startSpan("invoke_agent recon-sub");
          sub.end();
          model.end();
          root.end();
        },
      );

      // Normal-path flush: everything is on the wire before completion.
      await runtime.shutdown();

      const [body] = await receiver.waitForRequests(1);
      const resourceSpans = (
        body as {
          resourceSpans?: Array<{
            scopeSpans?: Array<{ spans?: Array<{ name?: string }> }>;
          }>;
        }
      ).resourceSpans;
      const names =
        resourceSpans?.[0]?.scopeSpans?.[0]?.spans?.map((s) => s.name) ?? [];
      expect(names).toContain("invoke_agent default");
      expect(names).toContain("ai.streamText");
      expect(names).toContain("invoke_agent recon-sub");
    } finally {
      await new Promise((resolve) => receiver.server.close(resolve));
    }
  });
});

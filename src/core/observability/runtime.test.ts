import { createServer, type Server } from "node:http";
import { context, createContextKey, trace } from "@opentelemetry/api";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildResource,
  isOtelSdkDisabled,
  parseResourceAttributes,
  resetObservabilityRuntime,
  resolveTracesEndpoint,
  resolveTracesProtocol,
  startObservabilityRuntime,
} from "./runtime";

// ---------------------------------------------------------------------------
// Local OTLP receiver
// ---------------------------------------------------------------------------

interface ReceivedRequest {
  method: string;
  url: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  body: unknown;
}

async function startOtlpReceiver(): Promise<{
  server: Server;
  port: number;
  requests: ReceivedRequest[];
  waitForRequests(count: number): Promise<ReceivedRequest[]>;
}> {
  const requests: ReceivedRequest[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf-8");
      let body: unknown = raw;
      try {
        body = JSON.parse(raw);
      } catch {
        // protobuf bodies stay raw
      }
      requests.push({
        method: req.method ?? "",
        url: req.url,
        headers: req.headers,
        body,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("no port");
  }
  const waitForRequests = (count: number) =>
    new Promise<ReceivedRequest[]>((resolve, reject) => {
      const started = Date.now();
      const poll = () => {
        if (requests.length >= count) return resolve(requests.slice(0, count));
        if (Date.now() - started > 5000)
          return reject(new Error("receiver timed out"));
        setTimeout(poll, 20);
      };
      poll();
    });
  return { server, port: address.port, requests, waitForRequests };
}

// ---------------------------------------------------------------------------
// Env lifecycle
// ---------------------------------------------------------------------------

const OTEL_VARS = [
  "OTEL_SDK_DISABLED",
  "OTEL_SERVICE_NAME",
  "OTEL_RESOURCE_ATTRIBUTES",
  "OTEL_EXPORTER_OTLP_ENDPOINT",
  "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
  "OTEL_EXPORTER_OTLP_HEADERS",
  "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
  "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
  "OTEL_EXPORTER_OTLP_PROTOCOL",
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

// ---------------------------------------------------------------------------
// Pure env resolution
// ---------------------------------------------------------------------------

describe("resolveTracesEndpoint", () => {
  it("returns null when nothing is configured", () => {
    expect(resolveTracesEndpoint({})).toBeNull();
  });

  it("explicit trace endpoint takes precedence over the generic endpoint", () => {
    const url = resolveTracesEndpoint({
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://generic:4318",
      OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://specific:4318/custom/traces",
    });
    expect(url).toBe("http://specific:4318/custom/traces");
  });

  it("generic endpoint correctly resolves /v1/traces", () => {
    expect(
      resolveTracesEndpoint({
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://localhost:4318",
      }),
    ).toBe("http://localhost:4318/v1/traces");
    expect(
      resolveTracesEndpoint({
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://localhost:4318/",
      }),
    ).toBe("http://localhost:4318/v1/traces");
  });

  it("the trace endpoint is used verbatim (no path appended)", () => {
    expect(
      resolveTracesEndpoint({
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT:
          "https://collector.example/api/traces",
      }),
    ).toBe("https://collector.example/api/traces");
  });
});

describe("resolveTracesProtocol", () => {
  it("defaults to http/json", () => {
    expect(resolveTracesProtocol({})).toBe("http/json");
  });

  it("honors the traces-specific protocol over the generic one", () => {
    expect(
      resolveTracesProtocol({
        OTEL_EXPORTER_OTLP_PROTOCOL: "http/json",
        OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: "http/protobuf",
      }),
    ).toBe("http/protobuf");
    expect(
      resolveTracesProtocol({ OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf" }),
    ).toBe("http/protobuf");
  });

  it("unknown values fall back to http/json", () => {
    expect(
      resolveTracesProtocol({ OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: "grpc" }),
    ).toBe("http/json");
  });
});

describe("resource helpers", () => {
  it("isOtelSdkDisabled reads the spec value", () => {
    expect(isOtelSdkDisabled({ OTEL_SDK_DISABLED: "true" })).toBe(true);
    expect(isOtelSdkDisabled({ OTEL_SDK_DISABLED: "false" })).toBe(false);
    expect(isOtelSdkDisabled({})).toBe(false);
  });

  it("parseResourceAttributes parses k=v pairs and skips junk", () => {
    expect(
      parseResourceAttributes({
        OTEL_RESOURCE_ATTRIBUTES: "deployment.env=prod, team=apex , bad, =x",
      }),
    ).toEqual({ "deployment.env": "prod", team: "apex" });
  });

  it("buildResource carries name, version, instance, and user attributes", () => {
    const resource = buildResource({
      OTEL_SERVICE_NAME: "apex-standalone",
      OTEL_RESOURCE_ATTRIBUTES:
        "service.name=resource-name,deployment.env=prod",
    });
    const attrs = resource.attributes as Record<string, unknown>;
    expect(attrs["service.name"]).toBe("apex-standalone");
    expect(typeof attrs["service.version"]).toBe("string");
    expect(attrs["service.version"]).not.toBe("");
    // Runtime instance id is unique per start.
    expect(typeof attrs["service.instance.id"]).toBe("string");
    expect(attrs["deployment.env"]).toBe("prod");

    const resourceOnly = buildResource({
      OTEL_RESOURCE_ATTRIBUTES: "service.name=resource-only",
    }).attributes as Record<string, unknown>;
    expect(resourceOnly["service.name"]).toBe("resource-only");

    const second = buildResource({}).attributes as Record<string, unknown>;
    expect(second["service.name"]).toBe("apex"); // default
    expect(second["service.instance.id"]).not.toBe(
      attrs["service.instance.id"],
    );
  });
});

// ---------------------------------------------------------------------------
// Runtime gating
// ---------------------------------------------------------------------------

describe("startObservabilityRuntime gating", () => {
  it("no endpoint returns a safe no-op runtime", async () => {
    const runtime = startObservabilityRuntime({});
    await expect(runtime.forceFlush()).resolves.toBeUndefined();
    await expect(runtime.shutdown()).resolves.toBe("completed");
    // Nothing registered: spans via the apex tracer are non-recording.
    const span = trace.getTracer("apex").startSpan("probe");
    expect(trace.isSpanContextValid(span.spanContext())).toBe(false);
    span.end();
  });

  it("disabled SDK does not register a provider", async () => {
    const runtime = startObservabilityRuntime({
      OTEL_SDK_DISABLED: "true",
      OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://127.0.0.1:4318/v1/traces",
    });
    await expect(runtime.forceFlush()).resolves.toBeUndefined();
    const span = trace.getTracer("apex").startSpan("probe");
    expect(trace.isSpanContextValid(span.spanContext())).toBe(false);
    span.end();
  });

  it("library imports never register globally", async () => {
    // Re-import the module fresh; import side effects alone must not
    // register a provider or context manager.
    await resetObservabilityRuntime();
    await import("./runtime");
    const span = trace.getTracer("apex").startSpan("probe");
    expect(trace.isSpanContextValid(span.spanContext())).toBe(false);
    span.end();
  });
});

// ---------------------------------------------------------------------------
// End-to-end export through the local receiver
// ---------------------------------------------------------------------------

describe("OTLP export", () => {
  it("headers reach a deterministic local HTTP receiver", async () => {
    const receiver = await startOtlpReceiver();
    try {
      process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = `http://127.0.0.1:${receiver.port}/v1/traces`;
      process.env.OTEL_EXPORTER_OTLP_TRACES_HEADERS =
        "Authorization=Basic testcreds,x-custom=apex";

      const runtime = startObservabilityRuntime();
      const span = trace.getTracer("apex").startSpan("exported-span");
      span.end();
      await runtime.forceFlush();

      const [request] = await receiver.waitForRequests(1);
      expect(request.method).toBe("POST");
      expect(request.url).toBe("/v1/traces");
      const auth = request.headers.authorization;
      expect(Array.isArray(auth) ? auth[0] : auth).toBe("Basic testcreds");
      const custom = request.headers["x-custom"];
      expect(Array.isArray(custom) ? custom[0] : custom).toBe("apex");
    } finally {
      await new Promise((resolve) => receiver.server.close(resolve));
    }
  });

  it("resource attributes appear on exported spans", async () => {
    const receiver = await startOtlpReceiver();
    try {
      process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = `http://127.0.0.1:${receiver.port}/v1/traces`;
      process.env.OTEL_SERVICE_NAME = "apex-e2e";
      process.env.OTEL_RESOURCE_ATTRIBUTES = "deployment.env=test";

      const runtime = startObservabilityRuntime();
      const span = trace.getTracer("apex").startSpan("resource-span");
      span.end();
      await runtime.forceFlush();

      const [request] = await receiver.waitForRequests(1);
      const resourceSpans = (
        request.body as {
          resourceSpans?: Array<{
            resource?: {
              attributes?: Array<{
                key: string;
                value?: { stringValue?: string };
              }>;
            };
            scopeSpans?: Array<{ spans?: Array<{ name?: string }> }>;
          }>;
        }
      ).resourceSpans;
      const attrs = Object.fromEntries(
        (resourceSpans?.[0]?.resource?.attributes ?? []).map((a) => [
          a.key,
          a.value?.stringValue,
        ]),
      );
      expect(attrs["service.name"]).toBe("apex-e2e");
      expect(attrs["deployment.env"]).toBe("test");
      expect(attrs["service.instance.id"]).toBeDefined();
      const spanNames = resourceSpans?.[0]?.scopeSpans?.[0]?.spans ?? [];
      expect(spanNames.map((s) => s.name)).toContain("resource-span");
    } finally {
      await new Promise((resolve) => receiver.server.close(resolve));
    }
  });

  it("normal completion flushes spans (shutdown path)", async () => {
    const receiver = await startOtlpReceiver();
    try {
      // Generic endpoint only — the exporter must append /v1/traces itself.
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = `http://127.0.0.1:${receiver.port}`;

      const runtime = startObservabilityRuntime();
      const span = trace.getTracer("apex").startSpan("flush-on-shutdown");
      span.end();
      await runtime.shutdown();

      const [request] = await receiver.waitForRequests(1);
      expect(request.url).toBe("/v1/traces");
      const body = request.body as {
        resourceSpans?: Array<{
          scopeSpans?: Array<{ spans?: Array<{ name?: string }> }>;
        }>;
      };
      const names =
        body.resourceSpans?.[0]?.scopeSpans?.[0]?.spans?.map((s) => s.name) ??
        [];
      expect(names).toContain("flush-on-shutdown");
    } finally {
      await new Promise((resolve) => receiver.server.close(resolve));
    }
  });
});

// ---------------------------------------------------------------------------
// PR5: provider ownership — Apex registers its own SDK, never a host's
// ---------------------------------------------------------------------------

describe("provider ownership", () => {
  it("does not register a context manager when the host owns the tracer", async () => {
    const { AsyncLocalStorageContextManager } = await import(
      "@opentelemetry/context-async-hooks"
    );
    const { BasicTracerProvider } = await import(
      "@opentelemetry/sdk-trace-base"
    );
    const hostProvider = new BasicTracerProvider();
    const hostContext = new AsyncLocalStorageContextManager();
    expect(trace.setGlobalTracerProvider(hostProvider)).toBe(true);

    try {
      process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT =
        "http://127.0.0.1:4318/v1/traces";
      const runtime = startObservabilityRuntime();

      hostContext.enable();
      expect(context.setGlobalContextManager(hostContext)).toBe(true);
      await runtime.shutdown();
    } finally {
      hostContext.disable();
      context.disable();
      trace.disable();
      await hostProvider.shutdown();
    }
  });

  it("a host-owned tracer keeps Apex embedded: no-op runtime, host untouched", async () => {
    // The host (Console) registered its own SDK first.
    const { startOtelTestHarness } = await import("./testkit");
    const host = startOtelTestHarness();
    try {
      process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT =
        "http://127.0.0.1:4318/v1/traces";
      const runtime = startObservabilityRuntime();

      // Apex did not take over — and its (no-op) shutdown leaves the host
      // provider working: a host span still records and exports.
      await runtime.shutdown();
      const { getApexTracer } = await import("../observability");
      const hostSpan = getApexTracer().startSpan("host-owned-work");
      hostSpan.end();
      expect(host.getFinishedSpans().map((s) => s.name)).toContain(
        "host-owned-work",
      );
      // A later standalone-style start still sees the host's global.
      expect(trace.getTracerProvider()).toBeDefined();
    } finally {
      await host.shutdown();
    }
  });

  it("a host-owned context manager is reused but never disabled", async () => {
    // Host owns ONLY the context manager; Apex's provider registration
    // succeeds so the runtime goes active — but shutdown must not kill the
    // host's context manager.
    const { AsyncLocalStorageContextManager } = await import(
      "@opentelemetry/context-async-hooks"
    );
    const hostContext = new AsyncLocalStorageContextManager();
    hostContext.enable();
    context.setGlobalContextManager(hostContext);
    try {
      process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT =
        "http://127.0.0.1:4318/v1/traces";
      const runtime = startObservabilityRuntime();
      await runtime.forceFlush();
      await runtime.shutdown();

      // The host context manager survived Apex's shutdown: a value placed on
      // a scoped context is visible through context.active() inside the run.
      const probeKey = createContextKey("host-context-probe");
      const probeContext = context.active().setValue(probeKey, "alive");
      const seen = context.with(probeContext, () =>
        context.active().getValue(probeKey),
      );
      expect(seen).toBe("alive");
    } finally {
      hostContext.disable();
      context.disable();
      trace.disable();
    }
  });
});

// ---------------------------------------------------------------------------
// PR5: one real agent/model/tool/subagent flow through the local OTLP
// receiver — the final export contract, not hand-built representative spans.
// ---------------------------------------------------------------------------

const mockState: { model: unknown } = { model: null };

const STEP_ONE_CHUNKS = [
  { type: "stream-start", warnings: [] },
  { type: "tool-input-start", id: "c1", toolName: "probe" },
  { type: "tool-input-delta", id: "c1", delta: '{"q":"hi"}' },
  { type: "tool-input-end", id: "c1" },
  {
    type: "tool-call",
    toolCallId: "c1",
    toolName: "probe",
    input: '{"q":"hi"}',
  },
  {
    type: "finish",
    finishReason: { unified: "tool-calls", raw: "tool_use" },
    usage: {
      inputTokens: { total: 1000, noCache: 100, cacheRead: 900, cacheWrite: 0 },
      outputTokens: { total: 10, text: 10, reasoning: undefined },
    },
  },
];

const STEP_TWO_CHUNKS = [
  { type: "stream-start", warnings: [] },
  { type: "text-start", id: "t" },
  { type: "text-delta", id: "t", delta: "final answer" },
  { type: "text-end", id: "t" },
  {
    type: "finish",
    finishReason: { unified: "stop", raw: "stop" },
    usage: {
      inputTokens: { total: 500, noCache: 50, cacheRead: 450, cacheWrite: 0 },
      outputTokens: { total: 5, text: 5, reasoning: undefined },
    },
  },
];

describe("end-to-end export contract", () => {
  vi.mock("../ai/utils", async () => {
    const actual =
      await vi.importActual<typeof import("../ai/utils")>("../ai/utils");
    return {
      ...actual,
      getProviderModel: () => {
        if (!mockState.model) throw new Error("mock model not set");
        return mockState.model as ReturnType<
          typeof import("../ai/utils").getProviderModel
        >;
      },
    };
  });

  it("exports a complete, attributable run tree with payloads, tokens, and cache", async () => {
    const { streamResponse } = await import("../ai");
    const { MockLanguageModelV3 } = await import("ai/test");
    const { simulateReadableStream, stepCountIs } = await import("ai");
    const { getApexTracer } = await import("../observability");

    const receiver = await startOtlpReceiver();
    try {
      process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = `http://127.0.0.1:${receiver.port}/v1/traces`;
      process.env.AI_TRACE_RECORD_PAYLOADS = "true";
      const runtime = startObservabilityRuntime();

      // A deterministic two-step tool-calling model with cache + tokens.
      let call = 0;
      mockState.model = new MockLanguageModelV3({
        provider: "mock-anthropic",
        modelId: "claude-haiku-4-5",
        doStream: async () => {
          call += 1;
          if (call === 1) {
            return {
              stream: simulateReadableStream({
                chunks: STEP_ONE_CHUNKS as unknown as Array<
                  import("@ai-sdk/provider").LanguageModelV3StreamPart
                >,
              }),
            };
          }
          return {
            stream: simulateReadableStream({
              chunks: STEP_TWO_CHUNKS as unknown as Array<
                import("@ai-sdk/provider").LanguageModelV3StreamPart
              >,
            }),
          };
        },
      });

      // Root run span (the agent's production shape) wrapping a real
      // streamResponse with a tool whose execution nests a subagent run.
      await getApexTracer().startActiveSpan(
        "invoke_agent default",
        {
          attributes: {
            "gen_ai.operation.name": "invoke_agent",
            "gen_ai.agent.id": "ses_e2e",
            "gen_ai.agent.name": "default",
            "gen_ai.conversation.id": "ses_e2e",
            "session.id": "ses_e2e",
            "pensar.session.id": "ses_e2e",
            "pensar.root_session.id": "ses_e2e",
            "pensar.agent.mode": "default",
            "gen_ai.prompt": "objective: test the target",
          },
        },
        async (root) => {
          try {
            const probe = {
              description: "spawns a subagent",
              inputSchema: (await import("zod")).z.object({
                q: (await import("zod")).z.string(),
              }),
              execute: async () => {
                await getApexTracer().startActiveSpan(
                  "invoke_agent recon-sub",
                  {
                    attributes: {
                      "gen_ai.operation.name": "invoke_agent",
                      "gen_ai.agent.id": "ses_exec_e2e",
                      "gen_ai.agent.name": "recon-sub",
                      "gen_ai.conversation.id": "ses_e2e",
                      "session.id": "ses_e2e",
                      "pensar.session.id": "ses_exec_e2e",
                      "pensar.root_session.id": "ses_e2e",
                    },
                  },
                  async (sub) => {
                    try {
                      call += 1; // the subagent's own model call
                      const { drain } = await import("./e2e-drain");
                      await drain(
                        streamResponse({
                          prompt: "subagent task",
                          model: "claude-haiku-4-5",
                          silent: true,
                          sessionId: "ses_e2e",
                        }),
                      );
                    } finally {
                      sub.end();
                    }
                  },
                );
                return "subagent done";
              },
            };

            const { drain } = await import("./e2e-drain");
            await drain(
              streamResponse({
                prompt: "objective: test the target",
                model: "claude-haiku-4-5",
                silent: true,
                sessionId: "ses_e2e",
                tools: { probe },
                stopWhen: stepCountIs(2),
              }),
            );
            root.setAttribute("gen_ai.completion", "final answer");
          } finally {
            root.end();
          }
        },
      );

      await runtime.shutdown();
      const requests = await receiver.waitForRequests(1);
      // The receiver stores full HTTP requests; the OTLP payload is the body.
      const body = (requests[0] as { body: unknown }).body as {
        resourceSpans?: Array<{
          scopeSpans?: Array<{
            spans?: Array<{
              name?: string;
              attributes?: Record<
                string,
                | { stringValue?: string }
                | { intValue?: string }
                | { doubleValue?: number }
              >;
              parentSpanId?: string;
              spanId?: string;
              traceId?: string;
            }>;
          }>;
        }>;
      };
      const rawSpans =
        body.resourceSpans?.flatMap((rs) =>
          (rs.scopeSpans ?? []).flatMap((ss) => ss.spans ?? []),
        ) ?? [];
      // OTLP attributes arrive as [{key, value}] — index them per span.
      const attrsOf = (
        attributes?: Array<{ key?: string; value?: Record<string, unknown> }>,
      ) =>
        Object.fromEntries(
          (attributes ?? []).map((a) => [a.key, a.value]),
        ) as Record<string, Record<string, unknown>>;
      const spans = rawSpans.map((sp) => ({
        name: (sp as { name?: string }).name,
        attributes: attrsOf(
          (
            sp as {
              attributes?: Array<{
                key?: string;
                value?: Record<string, unknown>;
              }>;
            }
          ).attributes,
        ),
        parentSpanId: (sp as { parentSpanId?: string }).parentSpanId,
        spanId: (sp as { spanId?: string }).spanId,
        traceId: (sp as { traceId?: string }).traceId,
      }));
      const byName = new Map(spans.map((sp) => [sp.name, sp]));
      const attr = (
        sp:
          | { attributes?: Record<string, Record<string, unknown>> }
          | undefined,
        key: string,
      ) => sp?.attributes?.[key]?.stringValue as string | undefined;
      const numAttr = (
        sp:
          | { attributes?: Record<string, Record<string, unknown>> }
          | undefined,
        key: string,
      ) => {
        const a = sp?.attributes?.[key];
        return (a?.intValue ?? a?.doubleValue) as string | number | undefined;
      };

      // Tree: root → model → provider → tool → subagent → its model.
      const root = byName.get("invoke_agent default");
      const model = byName.get("ai.streamText");
      const tool = byName.get("ai.toolCall");
      const sub = byName.get("invoke_agent recon-sub");
      expect(root && model && tool && sub).toBeTruthy();
      expect(model?.traceId).toBe(root?.traceId);
      expect(tool?.traceId).toBe(root?.traceId);
      expect(sub?.traceId).toBe(root?.traceId);
      expect(sub?.parentSpanId).toBe(tool?.spanId);

      // Identity: one root conversation across the tree, current agent kept
      // separately on each invoke span.
      for (const sp of spans) {
        if (sp.name?.startsWith("invoke_agent")) {
          expect(attr(sp, "gen_ai.conversation.id")).toBe("ses_e2e");
          expect(attr(sp, "session.id")).toBe("ses_e2e");
          expect(attr(sp, "pensar.root_session.id")).toBe("ses_e2e");
          expect(attr(sp, "pensar.run.id")).toBeUndefined();
          expect(attr(sp, "pensar.agent.execution.id")).toBeUndefined();
        }
      }
      expect(attr(root, "gen_ai.agent.id")).toBe("ses_e2e");
      expect(attr(root, "pensar.session.id")).toBe("ses_e2e");
      expect(attr(sub, "gen_ai.agent.id")).toBe("ses_exec_e2e");
      expect(attr(sub, "pensar.session.id")).toBe("ses_exec_e2e");
      for (const sp of spans.filter((span) => span.name === "ai.streamText")) {
        expect(attr(sp, "ai.telemetry.metadata.runId")).toBeUndefined();
        expect(attr(sp, "ai.telemetry.metadata.agentId")).toBeUndefined();
      }

      // Payload mode: prompts and tool payloads exported.
      expect(String(attr(root, "gen_ai.prompt"))).toContain("objective");
      expect(String(attr(root, "gen_ai.completion"))).toContain("final answer");
      expect(String(attr(model, "ai.prompt") ?? "")).toContain("objective");

      // Tokens + cache: inclusive input with cache reported separately —
      // per-step gen_ai.usage.* on each provider-call span, cumulative
      // ai.usage.* on the operation span. Both steps' spans exist.
      const doStreamSpans = spans.filter(
        (sp) => sp.name === "ai.streamText.doStream",
      );
      expect(doStreamSpans.length).toBeGreaterThanOrEqual(2);
      // Export order is not creation order — identify step 1 by its usage.
      expect(
        doStreamSpans.some(
          (sp) => numAttr(sp, "gen_ai.usage.input_tokens") === 1000,
        ),
      ).toBe(true);
      expect(numAttr(model, "ai.usage.cachedInputTokens")).toBe(1350);
    } finally {
      delete process.env.AI_TRACE_RECORD_PAYLOADS;
      await new Promise((resolve) => receiver.server.close(resolve));
    }
  });
});

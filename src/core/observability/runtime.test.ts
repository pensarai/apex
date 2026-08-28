import { createServer, type Server } from "node:http";
import { trace } from "@opentelemetry/api";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
    await expect(runtime.shutdown()).resolves.toBeUndefined();
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

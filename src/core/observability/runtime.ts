import { randomUUID } from "node:crypto";
import { context, trace } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPExporterBase } from "@opentelemetry/otlp-exporter-base";
import {
  convertLegacyHttpOptions,
  createOtlpHttpExportDelegate,
} from "@opentelemetry/otlp-exporter-base/node-http";
import {
  ProtobufTraceSerializer,
  TraceExporterMetricsHelper,
} from "@opentelemetry/otlp-transformer";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  BasicTracerProvider,
  BatchSpanProcessor,
  type SpanExporter,
} from "@opentelemetry/sdk-trace-base";
import { version as apexVersion } from "../../../package.json";

/**
 * Optional standalone OTLP/HTTP trace runtime. Apex keeps OTel disabled
 * unless an endpoint is explicitly configured — library imports never
 * register a global provider; only the standalone CLI/TUI entrypoints call
 * {@link startObservabilityRuntime}. Embedded hosts (Console) own their own
 * SDK and must not have Apex install a competing global provider.
 */

export interface ObservabilityRuntime {
  forceFlush(): Promise<void>;
  shutdown(): Promise<void>;
}

const NOOP_RUNTIME: ObservabilityRuntime = {
  async forceFlush() {},
  async shutdown() {},
};

type Env = Record<string, string | undefined>;

export function isOtelSdkDisabled(env: Env): boolean {
  return env.OTEL_SDK_DISABLED === "true";
}

/**
 * Resolve the trace export URL: the signal-specific endpoint wins verbatim;
 * otherwise the generic endpoint gets `v1/traces` appended. Mirrors the
 * OTel spec (and the exporter's own env handling) so the enabled-check and
 * the exporter agree. Returns null when nothing is configured.
 */
export function resolveTracesEndpoint(env: Env): string | null {
  const specific = env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT?.trim();
  if (specific) return specific;
  const generic = env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim();
  if (!generic) return null;
  return `${generic.endsWith("/") ? generic : `${generic}/`}v1/traces`;
}

export type OtlpProtocol = "http/json" | "http/protobuf";

export function resolveTracesProtocol(env: Env): OtlpProtocol {
  const raw = (
    env.OTEL_EXPORTER_OTLP_TRACES_PROTOCOL ??
    env.OTEL_EXPORTER_OTLP_PROTOCOL ??
    ""
  ).trim();
  return raw === "http/protobuf" ? "http/protobuf" : "http/json";
}

/** Parse `k1=v1,k2=v2` from OTEL_RESOURCE_ATTRIBUTES into a record. */
export function parseResourceAttributes(env: Env): Record<string, string> {
  const raw = env.OTEL_RESOURCE_ATTRIBUTES;
  if (!raw) return {};
  const attrs: Record<string, string> = {};
  for (const pair of raw.split(",")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const key = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (key && value) attrs[key] = value;
  }
  return attrs;
}

/** Service resource: name, version, per-process runtime instance, user attrs. */
export function buildResource(env: Env) {
  return resourceFromAttributes({
    "service.name": env.OTEL_SERVICE_NAME?.trim() || "apex",
    "service.version": apexVersion,
    "service.instance.id": randomUUID(),
    ...parseResourceAttributes(env),
  });
}

/**
 * The official exporter package hardcodes JSON serialization; protobuf is
 * composed from the public building blocks with the same env-driven
 * configuration (endpoint precedence, header merge, timeout, compression).
 */
function createTraceExporter(protocol: OtlpProtocol): SpanExporter {
  if (protocol === "http/json") {
    return new OTLPTraceExporter();
  }
  return new OTLPExporterBase(
    createOtlpHttpExportDelegate(
      convertLegacyHttpOptions({}, "TRACES", "v1/traces", {
        "Content-Type": "application/x-protobuf",
      }),
      ProtobufTraceSerializer,
      // OTEL_COMPONENT_TYPE_VALUE_OTLP_HTTP_SPAN_EXPORTER (unstable semconv,
      // inlined — not exported by the exporter package).
      "otlp_http_span_exporter",
      TraceExporterMetricsHelper,
      undefined,
    ),
  );
}

let activeRuntime: ObservabilityRuntime | null = null;

/**
 * Start the standalone observability runtime. Safe to call from multiple
 * entrypoints (CLI then TUI): the first real runtime wins and later calls
 * return it. Returns a no-op runtime — registering nothing — when the SDK is
 * disabled (`OTEL_SDK_DISABLED=true`) or no OTLP endpoint is configured.
 */
export function startObservabilityRuntime(
  env: Env = process.env,
): ObservabilityRuntime {
  if (activeRuntime) return activeRuntime;
  if (isOtelSdkDisabled(env)) return NOOP_RUNTIME;
  if (!resolveTracesEndpoint(env)) return NOOP_RUNTIME;

  const exporter = createTraceExporter(resolveTracesProtocol(env));
  const provider = new BasicTracerProvider({
    resource: buildResource(env),
    spanProcessors: [new BatchSpanProcessor(exporter)],
  });
  const contextManager = new AsyncLocalStorageContextManager();
  contextManager.enable();

  trace.setGlobalTracerProvider(provider);
  context.setGlobalContextManager(contextManager);

  const runtime: ObservabilityRuntime = {
    async forceFlush() {
      await provider.forceFlush();
    },
    async shutdown() {
      activeRuntime = null;
      await provider.shutdown();
      contextManager.disable();
      // Reset globals so a later start (or the host's own SDK) begins clean.
      trace.disable();
      context.disable();
    },
  };
  activeRuntime = runtime;
  return runtime;
}

/** Test/teardown hook: stop any active runtime and reset the singleton. */
export async function resetObservabilityRuntime(): Promise<void> {
  if (activeRuntime) {
    await activeRuntime.shutdown();
    return;
  }
  trace.disable();
  context.disable();
}

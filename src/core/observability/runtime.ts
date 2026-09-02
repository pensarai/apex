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
  type SpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { version as apexVersion } from "../../../package.json";
import { endAllActiveRootSpans } from "./active-root-spans";

/**
 * Optional standalone OTLP/HTTP trace runtime. Apex keeps OTel disabled
 * unless an endpoint is explicitly configured — library imports never
 * register a global provider; only the standalone CLI/TUI entrypoints call
 * {@link startObservabilityRuntime}. Embedded hosts (Console) own their own
 * SDK and must not have Apex install a competing global provider.
 */

export type ObservabilityShutdownResult = "completed" | "timed-out";

export interface ObservabilityRuntime {
  forceFlush(): Promise<void>;
  /** Idempotent and bounded: ends active root spans, flushes, shuts down. */
  shutdown(): Promise<ObservabilityShutdownResult>;
}

/** Options for {@link startObservabilityRuntime}. */
export interface StartObservabilityRuntimeOptions {
  /** Bound on shutdown (flush + exporter teardown); default 5000ms. */
  shutdownTimeoutMs?: number;
  /** Replace the default BatchSpanProcessor(OTLP exporter) — tests. */
  spanProcessors?: SpanProcessor[];
}

const DEFAULT_SHUTDOWN_TIMEOUT_MS = 5_000;

function withTimeout(
  promise: Promise<void>,
  timeoutMs: number,
): Promise<ObservabilityShutdownResult> {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (result: ObservabilityShutdownResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => settle("timed-out"), timeoutMs);
    promise.then(
      () => settle("completed"),
      () => settle("completed"),
    );
  });
}

const NOOP_RUNTIME: ObservabilityRuntime = {
  async forceFlush() {},
  async shutdown() {
    return "completed";
  },
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
  const resourceAttributes = parseResourceAttributes(env);
  return resourceFromAttributes({
    "service.version": apexVersion,
    "service.instance.id": randomUUID(),
    ...resourceAttributes,
    "service.name":
      env.OTEL_SERVICE_NAME?.trim() ||
      resourceAttributes["service.name"] ||
      "apex",
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
  opts?: StartObservabilityRuntimeOptions,
): ObservabilityRuntime {
  if (activeRuntime) return activeRuntime;
  if (isOtelSdkDisabled(env)) return NOOP_RUNTIME;
  if (!resolveTracesEndpoint(env)) return NOOP_RUNTIME;

  const shutdownTimeoutMs =
    opts?.shutdownTimeoutMs ?? DEFAULT_SHUTDOWN_TIMEOUT_MS;
  const exporter = createTraceExporter(resolveTracesProtocol(env));
  const provider = new BasicTracerProvider({
    resource: buildResource(env),
    spanProcessors: opts?.spanProcessors ?? [new BatchSpanProcessor(exporter)],
  });
  const contextManager = new AsyncLocalStorageContextManager();
  contextManager.enable();

  trace.setGlobalTracerProvider(provider);
  context.setGlobalContextManager(contextManager);

  let shutdownPromise: Promise<ObservabilityShutdownResult> | null = null;
  const runtime: ObservabilityRuntime = {
    async forceFlush() {
      await provider.forceFlush();
    },
    shutdown() {
      // Idempotent: every caller awaits the same bounded shutdown.
      if (!shutdownPromise) {
        const shutdownWork = (async () => {
          // End in-flight root runs first so their spans still export…
          endAllActiveRootSpans();
          // …then flush explicitly before processor/exporter teardown.
          try {
            await provider.forceFlush();
          } finally {
            await provider.shutdown();
          }
        })();
        shutdownPromise = withTimeout(shutdownWork, shutdownTimeoutMs)
          .then((result) => {
            contextManager.disable();
            // Reset globals so a later start (or the host's own SDK) begins clean.
            trace.disable();
            context.disable();
            return result;
          })
          .finally(() => {
            activeRuntime = null;
          });
      }
      return shutdownPromise;
    },
  };
  activeRuntime = runtime;
  return runtime;
}

/**
 * Standalone-process exit wiring: signals and fatal errors run the bounded
 * runtime shutdown before exiting — never a direct process.exit() while a
 * flush could still complete. `cleanup` runs synchronously before the flush
 * (entrypoint teardown such as renderer destruction); fatal errors are
 * reported after cleanup — so the TUI has left the alternate screen buffer
 * and the output survives — and preserved via exit code 1.
 */
export function installObservabilityExitHandlers(
  runtime: ObservabilityRuntime,
  opts?: {
    /** Synchronous entrypoint teardown before the flush. */
    cleanup?: (code: number) => void;
    /** Report a fatal error (entrypoints own their logging). */
    onError?: (
      error: unknown,
      source: "uncaughtException" | "unhandledRejection",
    ) => void;
  },
): (
  code: number,
  error?: unknown,
  source?: "uncaughtException" | "unhandledRejection",
) => Promise<void> {
  let exitPromise: Promise<void> | null = null;
  let exitCode = 0;
  let fatalSeen = false;
  const reportError = (
    error: unknown,
    source: "uncaughtException" | "unhandledRejection",
  ) => {
    try {
      opts?.onError?.(error, source);
    } catch {
      // Error reporting must not block the process exit path.
    }
  };
  const exitWith = (
    code: number,
    error?: unknown,
    source?: "uncaughtException" | "unhandledRejection",
  ) => {
    let pendingReport: (() => void) | null = null;
    if (error !== undefined && !fatalSeen) {
      fatalSeen = true;
      exitCode = 1;
      const fatalSource = source ?? "uncaughtException";
      pendingReport = () => reportError(error, fatalSource);
    } else if (!fatalSeen && exitCode === 0) {
      exitCode = code;
    }
    if (exitPromise) {
      // Cleanup already ran (terminal restored) — a late fatal reports now.
      pendingReport?.();
      return exitPromise;
    }
    try {
      opts?.cleanup?.(code);
    } catch (cleanupError) {
      if (!fatalSeen) {
        fatalSeen = true;
        exitCode = 1;
        pendingReport = () => reportError(cleanupError, "uncaughtException");
      }
    }
    // Report only after entrypoint teardown: the TUI must leave the
    // alternate screen buffer first or the console output is discarded.
    pendingReport?.();
    exitPromise = runtime
      .shutdown()
      .catch(() => {})
      .then(() => process.exit(exitCode));
    return exitPromise;
  };

  process.on("SIGINT", () => void exitWith(130));
  process.on("SIGTERM", () => void exitWith(143));
  process.on(
    "uncaughtException",
    (error) => void exitWith(1, error, "uncaughtException"),
  );
  process.on(
    "unhandledRejection",
    (reason) => void exitWith(1, reason, "unhandledRejection"),
  );
  return exitWith;
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

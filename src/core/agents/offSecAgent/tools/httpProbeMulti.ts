import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { hostnameFor } from "./_safetyCaps";

const MAX_URLS = 100;
const MAX_CONCURRENCY = 10;
const DEFAULT_CONCURRENCY = 5;
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_INLINE_BODY = 500;

export const httpProbeMultiInputSchema = z.object({
  urls: z
    .array(z.string().url())
    .min(1)
    .max(MAX_URLS)
    .describe(
      `Absolute URLs to probe (max ${MAX_URLS} per call). For dirbuster / endpoint-enumeration / API-version-sweep scenarios.`,
    ),
  method: z
    .enum(["GET", "HEAD", "POST", "OPTIONS"])
    .default("GET")
    .describe(
      "HTTP method. Use HEAD for existence probes (cheapest). POST only when you intentionally want to trigger state changes.",
    ),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe(
      "Extra HTTP headers merged into every probe (on top of default auth headers).",
    ),
  body: z
    .string()
    .optional()
    .describe(
      "Optional request body (only meaningful for POST). Same body is sent to every URL.",
    ),
  concurrency: z
    .number()
    .int()
    .positive()
    .max(MAX_CONCURRENCY)
    .optional()
    .describe(
      `Maximum simultaneous in-flight requests (default ${DEFAULT_CONCURRENCY}, max ${MAX_CONCURRENCY}). Higher finishes faster but is harder on target rate-limits.`,
    ),
  timeoutMs: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(`Per-request timeout in ms (default ${DEFAULT_TIMEOUT_MS}).`),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Enumerating 50 common admin paths to check for exposed endpoints')",
    ),
});

export type HttpProbeMultiInput = z.infer<typeof httpProbeMultiInputSchema>;

type ProbeResult = {
  url: string;
  status: number | null;
  statusText?: string;
  bodyPreview?: string;
  contentLength?: number | null;
  durationMs: number;
  error?: string;
  /** True if the response pattern looks "unexpectedly available" — 2xx/3xx where a 404/403 was more likely. */
  unexpected: boolean;
};

export type HttpProbeMultiResult = {
  success: boolean;
  results: ProbeResult[];
  totalDuration: number;
  capViolations: number;
};

function isUnexpectedOK(status: number): boolean {
  return status >= 200 && status < 400;
}

async function probeOne(
  ctx: ToolContext,
  url: string,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
): Promise<ProbeResult> {
  const startedAt = Date.now();

  if (ctx.safetyCaps) {
    const v = await ctx.safetyCaps.checkAndConsume(hostnameFor(url));
    if (v) {
      return {
        url,
        status: null,
        durationMs: Date.now() - startedAt,
        error: `Safety cap: ${v.message}`,
        unexpected: false,
      };
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method,
      headers,
      body: method === "POST" ? body : undefined,
      signal: controller.signal,
      redirect: "manual",
    });
    const contentLength =
      parseInt(resp.headers.get("content-length") ?? "", 10) || null;
    let bodyPreview: string | undefined;
    if (method !== "HEAD") {
      const text = await resp.text();
      bodyPreview =
        text.length > MAX_INLINE_BODY
          ? `${text.slice(0, MAX_INLINE_BODY)}...(truncated from ${text.length}B)`
          : text;
    }
    return {
      url,
      status: resp.status,
      statusText: resp.statusText,
      bodyPreview,
      contentLength,
      durationMs: Date.now() - startedAt,
      unexpected: isUnexpectedOK(resp.status),
    };
  } catch (error) {
    return {
      url,
      status: null,
      durationMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : String(error),
      unexpected: false,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<ProbeResult>,
): Promise<ProbeResult[]> {
  const results: ProbeResult[] = new Array(items.length);
  let index = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = index++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

export function httpProbeMulti(ctx: ToolContext) {
  return tool({
    description: `Probe up to 100 URLs in parallel (concurrency-capped) and return a result per URL.

Use for:
  • Directory bruteforce / endpoint enumeration (probe 50 common paths)
  • API-version sweeps (/v1, /v2, /v3, /api/internal, …)
  • "Does my WAF block all 10 OWASP categories?" validation

Respects per-run safety caps. Auto-emits \`alert_raised\` for any URL that
returns an unexpectedly successful (2xx/3xx) status when we were probing for
typically-404 paths. You should interpret bulk "expected 404" patterns
yourself — if 90% of probes return 404 and 5% return 200, those 5% are
the interesting ones.

Does NOT auto-emit for clean 404/403 sweeps (that's the happy path). Use
HEAD method when you only care about existence — cheaper on target infra.`,
    inputSchema: httpProbeMultiInputSchema,
    execute: async (input): Promise<HttpProbeMultiResult> => {
      const startedAt = Date.now();
      const concurrency = Math.min(
        input.concurrency ?? DEFAULT_CONCURRENCY,
        MAX_CONCURRENCY,
      );
      const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      const mergedHeaders: Record<string, string> = {
        ...(ctx.defaultHeaders ?? {}),
        ...(input.headers ?? {}),
      };

      const results = await runWithConcurrency(input.urls, concurrency, (url) =>
        probeOne(ctx, url, input.method, mergedHeaders, input.body, timeoutMs),
      );

      const capViolations = results.filter((r) =>
        r.error?.startsWith("Safety cap"),
      ).length;

      // Emit alert_raised per unexpected-OK probe
      for (const r of results) {
        if (r.unexpected) {
          ctx.eventBus?.emit("detection_event", {
            kind: "alert_raised",
            severity: "medium",
            source: "rule-engine",
            summary: `Unexpected ${r.status} at ${r.url} — endpoint accessible when 404/403 was expected`,
            data: {
              url: r.url,
              status: r.status,
              statusText: r.statusText,
              contentLength: r.contentLength,
              bodyPreview: r.bodyPreview?.slice(0, 200),
              interpretation:
                "Probe returned a success code in a sweep that was expected to 404/403. Likely a leak/misconfig.",
            },
          });
        }
      }

      return {
        success: true,
        results,
        totalDuration: Date.now() - startedAt,
        capViolations,
      };
    },
  });
}

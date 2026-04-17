import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { hostnameFor } from "./_safetyCaps";

const MAX_COUNT = 50;
const MAX_CONCURRENCY = 20;
const DEFAULT_CONCURRENCY = 10;
const DEFAULT_TIMEOUT_MS = 10_000;

export const httpBurstInputSchema = z.object({
  url: z
    .string()
    .url()
    .describe("Target URL that will receive N concurrent requests."),
  count: z
    .number()
    .int()
    .positive()
    .max(MAX_COUNT)
    .describe(`Number of requests to send (max ${MAX_COUNT}).`),
  method: z
    .enum(["GET", "POST", "PUT", "PATCH", "DELETE"])
    .default("POST")
    .describe("HTTP method — POST is the common choice for race-condition tests."),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe("Extra headers merged into every request (on top of default auth headers)."),
  body: z
    .string()
    .optional()
    .describe(
      "Request body sent with every request. For unique-per-request payloads use bodyTemplate + {{i}} substitution.",
    ),
  bodyTemplate: z
    .string()
    .optional()
    .describe(
      'If set, overrides `body`: "{{i}}" placeholders are replaced with the request index (0..count-1), enabling unique-per-request payloads for race tests (e.g. \'{"promo":"SAVE10","reqId":"{{i}}"}\').',
    ),
  concurrency: z
    .number()
    .int()
    .positive()
    .max(MAX_CONCURRENCY)
    .optional()
    .describe(
      `Simultaneous in-flight requests (default ${DEFAULT_CONCURRENCY}, max ${MAX_CONCURRENCY}). High concurrency is the point — this is how we surface race conditions.`,
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
      "A concise, human-readable description (e.g., 'Firing 20 concurrent /checkout POSTs with the same promo code to test for TOCTOU race')",
    ),
});

export type HttpBurstInput = z.infer<typeof httpBurstInputSchema>;

type OneResult = {
  index: number;
  status: number | null;
  durationMs: number;
  bodyPreview?: string;
  error?: string;
};

export type HttpBurstResult = {
  success: boolean;
  url: string;
  method: string;
  count: number;
  statuses: number[];
  successCount: number;
  errorCount: number;
  durations: number[];
  raceDeltaMs: number; // max - min duration; small delta = good parallelism
  results: OneResult[];
};

function resolveBody(input: HttpBurstInput, i: number): string | undefined {
  if (input.bodyTemplate !== undefined) {
    return input.bodyTemplate.replace(/\{\{i\}\}/g, String(i));
  }
  return input.body;
}

async function fireOne(
  ctx: ToolContext,
  input: HttpBurstInput,
  i: number,
  mergedHeaders: Record<string, string>,
  timeoutMs: number,
): Promise<OneResult> {
  const startedAt = Date.now();
  const body = resolveBody(input, i);

  if (ctx.safetyCaps) {
    const v = await ctx.safetyCaps.checkAndConsume(hostnameFor(input.url));
    if (v) {
      return {
        index: i,
        status: null,
        durationMs: Date.now() - startedAt,
        error: `Safety cap: ${v.message}`,
      };
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(input.url, {
      method: input.method,
      headers: mergedHeaders,
      body: body,
      signal: controller.signal,
    });
    const text = await resp.text();
    return {
      index: i,
      status: resp.status,
      durationMs: Date.now() - startedAt,
      bodyPreview: text.slice(0, 500),
    };
  } catch (error) {
    return {
      index: i,
      status: null,
      durationMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runBurst(
  items: number[],
  concurrency: number,
  fn: (i: number) => Promise<OneResult>,
): Promise<OneResult[]> {
  const results: OneResult[] = new Array(items.length);
  let idx = 0;
  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    async () => {
      while (true) {
        const i = idx++;
        if (i >= items.length) return;
        results[i] = await fn(items[i]);
      }
    },
  );
  await Promise.all(workers);
  return results;
}

export function httpBurst(ctx: ToolContext) {
  return tool({
    description: `Fire N concurrent HTTP requests at a single URL (N up to 50) and report timing + status distribution.

Use for:
  • Race conditions / TOCTOU (the exact same promo code applied N times,
    or N concurrent state-changing POSTs that should be serialized)
  • Rate-limit validation (does target return 429 after X?)
  • Credential-stuffing simulation (does target lock the account?)
  • Load-sensitivity probing (consistent behavior under concurrency?)

Uses \`bodyTemplate\` with {{i}} substitution to generate unique-per-request
payloads (e.g. unique reqIds, usernames, etc.) — race tests often require
this to avoid request dedup.

Respects per-run safety caps — large bursts to a single host may block
requests after the per-host rate limit triggers. If that happens the tool
returns the partial burst and notes capViolations.

Returns \`raceDeltaMs\` = (max duration) - (min duration). Small values
(<50ms) indicate the requests really did arrive concurrently.`,
    inputSchema: httpBurstInputSchema,
    execute: async (input): Promise<HttpBurstResult> => {
      const concurrency = Math.min(
        input.concurrency ?? DEFAULT_CONCURRENCY,
        MAX_CONCURRENCY,
      );
      const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      const mergedHeaders: Record<string, string> = {
        ...(ctx.defaultHeaders ?? {}),
        ...(input.headers ?? {}),
      };
      const indices = Array.from({ length: input.count }, (_, i) => i);
      const results = await runBurst(indices, concurrency, (i) =>
        fireOne(ctx, input, i, mergedHeaders, timeoutMs),
      );

      const statuses = results
        .map((r) => r.status)
        .filter((s): s is number => s !== null);
      const successCount = results.filter(
        (r) => r.status !== null && r.status >= 200 && r.status < 400,
      ).length;
      const errorCount = results.filter((r) => !!r.error).length;
      const durations = results.map((r) => r.durationMs);
      const raceDeltaMs = durations.length
        ? Math.max(...durations) - Math.min(...durations)
        : 0;

      // Auto-emit alert_raised if the status mix suggests inconsistent
      // serialization: e.g. several 200 OK where the target ought to have
      // rejected duplicates after the first.
      const status200 = statuses.filter((s) => s === 200).length;
      if (status200 >= 2 && input.method !== "GET") {
        ctx.eventBus?.emit("detection_event", {
          kind: "alert_raised",
          severity: "high",
          source: "rule-engine",
          summary: `httpBurst: ${status200}/${input.count} ${input.method} requests to ${input.url} returned 200 — possible race/duplicate acceptance`,
          data: {
            url: input.url,
            method: input.method,
            successCount: status200,
            totalRequests: input.count,
            raceDeltaMs,
            statusDistribution: Object.fromEntries(
              Object.entries(
                statuses.reduce<Record<number, number>>((acc, s) => {
                  acc[s] = (acc[s] ?? 0) + 1;
                  return acc;
                }, {}),
              ),
            ),
            interpretation:
              "Multiple state-changing requests returned 200 under concurrency. Likely a TOCTOU / race condition in the target's server-side uniqueness / idempotency logic.",
          },
        });
      }

      return {
        success: true,
        url: input.url,
        method: input.method,
        count: input.count,
        statuses,
        successCount,
        errorCount,
        durations,
        raceDeltaMs,
        results,
      };
    },
  });
}

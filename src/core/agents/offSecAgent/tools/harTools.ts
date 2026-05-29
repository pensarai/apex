import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { diffHarEntries } from "../../../har/diff";
import { filterHarByScope } from "../../../har/scope";
import { type HarEntry, type HarHeader, parseHar } from "../../../har/types";
import { targetFetch } from "../../../http/targetHeaders";
import {
  assertUrlInScope,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";

const BODY_PREVIEW_BYTES = 5_000;

const HarFilterSchema = z.object({
  host: z.string().optional(),
  method: z.string().optional(),
  status: z.number().optional(),
  pathRegex: z.string().optional(),
  hasAuth: z.boolean().optional(),
});

const ReplayMutationsSchema = z
  .object({
    headers: z.record(z.string()).optional(),
    queryParams: z.record(z.string()).optional(),
    body: z.string().optional(),
    credentialId: z.string().optional(),
  })
  .optional();

export function startHarCapture(ctx: ToolContext) {
  return tool({
    description: "Start a named HAR capture for the current browser session.",
    inputSchema: z.object({
      name: z
        .string()
        .describe("Short capture name, e.g. account-a-profile-flow"),
      toolCallDescription: z
        .string()
        .describe("Why this browser flow should be captured as HAR"),
    }),
    execute: async ({ name }) => {
      if (!ctx.browserSession) {
        return { success: false, error: "Browser session is not available" };
      }
      try {
        const result = await ctx.browserSession.beginHarCapture(name);
        return { success: true, ...result };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

export function stopHarCapture(ctx: ToolContext) {
  return tool({
    description:
      "Stop an active HAR capture and write it to the session evidence directory.",
    inputSchema: z.object({
      captureId: z
        .string()
        .describe("Capture ID returned by start_har_capture"),
      toolCallDescription: z
        .string()
        .describe("Why this HAR capture is complete"),
    }),
    execute: async ({ captureId }) => {
      if (!ctx.browserSession) {
        return { success: false, error: "Browser session is not available" };
      }
      try {
        const result = await ctx.browserSession.endHarCapture(
          captureId,
          harEvidenceDir(ctx),
        );
        return { success: true, ...result };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

export function getHarSummary(ctx: ToolContext) {
  return tool({
    description: "Summarize scoped entries from a captured HAR file.",
    inputSchema: z.object({
      harPath: z
        .string()
        .describe("Absolute path to a HAR file in this session"),
      filter: HarFilterSchema.optional(),
      limit: z.number().default(50).describe("Maximum entries to return"),
      toolCallDescription: z
        .string()
        .describe("Why this HAR summary is needed"),
    }),
    execute: async ({ harPath, filter, limit }) => {
      try {
        const entries = loadScopedEntries(ctx, harPath);
        const selected = applyHarFilter(entries, filter).slice(0, limit);
        return {
          success: true,
          harPath,
          totalEntries: entries.length,
          returnedEntries: selected.length,
          byHost: countBy(entries, (entry) => new URL(entry.request.url).host),
          byMethod: countBy(entries, (entry) => entry.request.method),
          byStatus: countBy(entries, (entry) => String(entry.response.status)),
          entries: selected.map(summarizeEntry),
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

export function harReplay(ctx: ToolContext) {
  return tool({
    description:
      "Replay one request from a captured HAR, optionally mutating headers, query parameters, body, or credential. Enforces target scope before sending.",
    inputSchema: z.object({
      harPath: z
        .string()
        .describe("Absolute path to a HAR file in this session"),
      entryId: z.string().describe("HAR entry _id from get_har_summary"),
      mutations: ReplayMutationsSchema,
      timeout: z.number().default(10000),
      toolCallDescription: z
        .string()
        .describe("Why this captured request should be replayed"),
    }),
    execute: async ({ harPath, entryId, mutations, timeout }) => {
      try {
        const entries = loadScopedEntries(ctx, harPath);
        const entry = entries.find((candidate) => candidate._id === entryId);
        if (!entry) {
          return { success: false, error: `Unknown HAR entry: ${entryId}` };
        }

        const replay = buildReplayRequest(ctx, entry, mutations);
        assertUrlInScope(replay.url, ctx);

        if (requiresReplayApproval(entry.request.method, mutations)) {
          if (!ctx.approvalGate) {
            return {
              success: false,
              error: "Approval gate is required for sensitive HAR replay",
            };
          }
          await ctx.approvalGate.requireApproval(
            "har_replay",
            `tc_${Date.now()}_${randomBytes(4).toString("hex")}`,
            {
              url: replay.url,
              method: replay.method,
              mutations,
            },
          );
        }

        const response = await fetchWithTimeout(ctx, replay, timeout);
        const body = await response.text();
        const bodyInfo = saveReplayBody(ctx, body);
        return {
          success: true,
          url: response.url,
          method: replay.method,
          status: response.status,
          statusText: response.statusText,
          headers: responseHeadersToRecord(response.headers),
          body: bodyInfo.preview,
          bodyPath: bodyInfo.path,
        };
      } catch (error) {
        if (error instanceof ScopeViolationError) {
          return { success: false, error: error.message };
        }
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

export function harDiff(ctx: ToolContext) {
  return tool({
    description:
      "Diff two session HARs and write a JSON report of authorization candidates.",
    inputSchema: z.object({
      accountAHarPath: z
        .string()
        .describe("Absolute path to the HAR captured as account A"),
      accountBHarPath: z
        .string()
        .describe("Absolute path to the HAR captured as account B"),
      outputPath: z
        .string()
        .optional()
        .describe("Optional session-local path for the JSON diff report"),
      toolCallDescription: z
        .string()
        .describe("Why these HAR files should be compared"),
    }),
    execute: async ({ accountAHarPath, accountBHarPath, outputPath }) => {
      try {
        const accountAEntries = loadScopedEntries(ctx, accountAHarPath);
        const accountBEntries = loadScopedEntries(ctx, accountBHarPath);
        const report = diffHarEntries(accountAEntries, accountBEntries);
        const path =
          outputPath ??
          join(harEvidenceDir(ctx), `idor-diff-${Date.now()}.json`);
        const resolvedOutput = assertSessionOutputPath(ctx, path);
        mkdirSync(dirname(resolvedOutput), { recursive: true });
        writeFileSync(resolvedOutput, JSON.stringify(report, null, 2));
        return { success: true, path: resolvedOutput, ...report };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

function harEvidenceDir(ctx: ToolContext): string {
  return join(ctx.session.rootPath, "evidence", "har");
}

function assertSessionPath(ctx: ToolContext, path: string): string {
  const resolved = resolve(path);
  const sessionRoot = resolve(ctx.session.rootPath);
  if (resolved !== sessionRoot && !resolved.startsWith(`${sessionRoot}/`)) {
    throw new Error(`HAR path is outside this session: ${path}`);
  }
  if (!existsSync(resolved)) {
    throw new Error(`HAR file not found: ${path}`);
  }
  return resolved;
}

function assertSessionOutputPath(ctx: ToolContext, path: string): string {
  const resolved = resolve(path);
  const sessionRoot = resolve(ctx.session.rootPath);
  if (resolved !== sessionRoot && !resolved.startsWith(`${sessionRoot}/`)) {
    throw new Error(`HAR output path is outside this session: ${path}`);
  }
  return resolved;
}

function loadScopedEntries(ctx: ToolContext, harPath: string): HarEntry[] {
  const resolved = assertSessionPath(ctx, harPath);
  const har = parseHar(readFileSync(resolved, "utf-8"));
  return filterHarByScope(har.log.entries, ctx);
}

function applyHarFilter(
  entries: HarEntry[],
  filter: z.infer<typeof HarFilterSchema> | undefined,
): HarEntry[] {
  if (!filter) return entries;
  const pathPattern = filter.pathRegex ? new RegExp(filter.pathRegex) : null;
  return entries.filter((entry) => {
    const url = new URL(entry.request.url);
    if (filter.host && url.host !== filter.host) return false;
    if (filter.method && entry.request.method !== filter.method) return false;
    if (filter.status && entry.response.status !== filter.status) return false;
    if (pathPattern && !pathPattern.test(url.pathname)) return false;
    if (filter.hasAuth !== undefined && hasAuth(entry) !== filter.hasAuth)
      return false;
    return true;
  });
}

function summarizeEntry(entry: HarEntry) {
  return {
    id: entry._id,
    method: entry.request.method,
    url: entry.request.url,
    status: entry.response.status,
    contentType: headerValue(entry.response.headers, "content-type"),
    sizeBytes: entry.response.content.size,
    hasAuth: hasAuth(entry),
    authHeaders: pickHeaders(entry.request.headers, [
      "authorization",
      "cookie",
    ]),
    setCookieHeaders: pickHeaders(entry.response.headers, ["set-cookie"]),
  };
}

function countBy(
  entries: HarEntry[],
  keyFn: (entry: HarEntry) => string,
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const entry of entries) {
    const key = keyFn(entry);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function headersToRecord(headers: HarHeader[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const header of headers) {
    result[header.name] = header.value;
  }
  return result;
}

function responseHeadersToRecord(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function headerValue(headers: HarHeader[], name: string): string | undefined {
  const lower = name.toLowerCase();
  return headers.find((header) => header.name.toLowerCase() === lower)?.value;
}

function pickHeaders(
  headers: HarHeader[],
  names: string[],
): Record<string, string> {
  const wanted = new Set(names.map((name) => name.toLowerCase()));
  const result: Record<string, string> = {};
  for (const header of headers) {
    if (wanted.has(header.name.toLowerCase())) {
      result[header.name] = header.value;
    }
  }
  return result;
}

function hasAuth(entry: HarEntry): boolean {
  return Boolean(
    headerValue(entry.request.headers, "authorization") ||
      headerValue(entry.request.headers, "cookie"),
  );
}

function buildReplayRequest(
  ctx: ToolContext,
  entry: HarEntry,
  mutations: z.infer<typeof ReplayMutationsSchema>,
): {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
} {
  const url = new URL(entry.request.url);
  const headers = headersToRecord(entry.request.headers);
  let body =
    entry.request.postData?.encoding === "base64" && entry.request.postData.text
      ? Buffer.from(entry.request.postData.text, "base64").toString("utf-8")
      : entry.request.postData?.text;

  if (mutations?.headers) {
    Object.assign(headers, mutations.headers);
  }
  if (mutations?.queryParams) {
    for (const [key, value] of Object.entries(mutations.queryParams)) {
      url.searchParams.set(key, value);
    }
  }
  if (mutations?.body !== undefined) {
    body = mutations.body;
  }
  if (mutations?.credentialId) {
    const credential = ctx.credentialManager?.resolve(mutations.credentialId);
    if (!credential) {
      throw new Error(`Unknown credential ID: ${mutations.credentialId}`);
    }
    if (credential.tokens?.bearerToken) {
      headers.Authorization = `Bearer ${credential.tokens.bearerToken}`;
    }
    if (credential.tokens?.cookies) {
      headers.Cookie = credential.tokens.cookies;
    }
    if (credential.tokens?.customHeaders) {
      Object.assign(headers, credential.tokens.customHeaders);
    }
  }

  return {
    url: url.toString(),
    method: entry.request.method,
    headers,
    body: ["GET", "HEAD"].includes(entry.request.method) ? undefined : body,
  };
}

function requiresReplayApproval(
  method: string,
  mutations: z.infer<typeof ReplayMutationsSchema>,
): boolean {
  if (["DELETE", "PUT", "PATCH"].includes(method.toUpperCase())) return true;
  if (mutations?.credentialId) return true;
  return Object.keys(mutations?.headers ?? {}).some((name) =>
    ["authorization", "cookie"].includes(name.toLowerCase()),
  );
}

async function fetchWithTimeout(
  ctx: ToolContext,
  replay: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body?: string;
  },
  timeout: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await targetFetch(resolverSessionFromCtx(ctx), replay.url, {
      method: replay.method,
      headers: replay.headers,
      body: replay.body,
      redirect: "manual",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

function saveReplayBody(
  ctx: ToolContext,
  body: string,
): { preview: string; path?: string } {
  if (body.length <= BODY_PREVIEW_BYTES) return { preview: body };
  const outputDir = join(ctx.session.logsPath, "har-replay-responses");
  mkdirSync(outputDir, { recursive: true });
  const path = join(outputDir, `response-${Date.now()}.txt`);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body);
  return {
    preview: `${body.slice(0, BODY_PREVIEW_BYTES)}...\n\n(truncated — full response saved to ${path})`,
    path,
  };
}

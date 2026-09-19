import { tool } from "ai";
import { z } from "zod";
import { resolveEffectiveHeaders } from "../../../http/targetHeaders";
import type { HeaderRecord } from "../../../http/types";
import { resolverSessionFromCtx } from "./scopeGuard";
import type { ToolContext } from "./types";

// Tool baselines used for out-of-scope research URLs (CVE writeups, vendor
// docs) — a recognisable UA avoids Cloudflare/Akamai bot challenges on
// `Bun/x.y` defaults. For in-scope URLs the resolver's values win.
const GETPAGE_USER_AGENT =
  "Mozilla/5.0 (compatible; PensarBot/1.0; +https://pensar.dev)";

const BASELINE_FALLBACK_HEADERS: HeaderRecord = {
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
};

function mergeBaselineHeaders(resolved: HeaderRecord): HeaderRecord {
  const present = new Set(Object.keys(resolved).map((k) => k.toLowerCase()));
  const out: HeaderRecord = { ...resolved };
  out["User-Agent"] = GETPAGE_USER_AGENT;
  for (const [name, value] of Object.entries(BASELINE_FALLBACK_HEADERS)) {
    if (!present.has(name.toLowerCase())) out[name] = value;
  }
  return out;
}

const MAX_CONTENT_LENGTH = 50_000;
const REQUEST_TIMEOUT = 30_000;
// Hard cap on response bytes actually buffered/decoded — `response.text()`
// buffers the whole body before truncation, so an oversized page exhausts
// memory first. 5 MiB is far beyond what a 50k-char text extraction needs.
const MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024;

const getPageInputSchema = z.object({
  url: z
    .string()
    .url()
    .describe("The URL of the page to fetch and extract content from."),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Fetching CVE details from NVD')",
    ),
});

type GetPageInput = z.infer<typeof getPageInputSchema>;

export interface GetPageResponse {
  success: boolean;
  url: string;
  title?: string;
  content?: string;
  error?: string;
}

function extractTitle(html: string): string | undefined {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return titleMatch?.[1]?.trim();
}

function extractTextContent(html: string): string {
  let text = html;

  // Remove script and style tags with their content
  text = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");
  text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");
  text = text.replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "");

  // Remove HTML comments
  text = text.replace(/<!--[\s\S]*?-->/g, "");

  // Remove all HTML tags
  text = text.replace(/<[^>]+>/g, " ");

  // Decode common HTML entities
  text = text
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'");

  // Normalize whitespace
  text = text.replace(/\s+/g, " ").trim();

  // Split into lines and remove empty ones
  const lines = text
    .split(/[.\n]/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  return lines.join("\n");
}

function bodyAbortError(): Error {
  const err = new Error("The operation was aborted");
  err.name = "AbortError";
  return err;
}

/**
 * Reads up to `maxBytes` into one owned buffer (per-chunk arrays are not a
 * memory bound), cancelling the reader past the cap. Never awaits `cancel()`
 * (it may never settle); aborts — including an already-aborted signal —
 * surface as AbortError, never as a clean end-of-body.
 */
async function readBodyCapped(
  response: Response,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<{ text: string; truncated: boolean }> {
  if (signal?.aborted) {
    response.body?.cancel().catch(() => {});
    throw bodyAbortError();
  }
  const body = response.body;
  if (!body) return { text: "", truncated: false };

  const reader = body.getReader();
  const onAbort = () => {
    reader.cancel().catch(() => {});
  };
  signal?.addEventListener("abort", onAbort, { once: true });

  let buf = new Uint8Array(Math.min(maxBytes, 64 * 1024));
  let received = 0;
  let truncated = false;

  const append = (value: Uint8Array, take: number) => {
    if (take <= 0) return;
    if (received + take > buf.byteLength) {
      // Geometric growth, hard-capped at maxBytes.
      let size = buf.byteLength;
      while (size < received + take && size < maxBytes) size *= 2;
      const next = new Uint8Array(Math.min(size, maxBytes));
      next.set(buf.subarray(0, received));
      buf = next;
    }
    buf.set(value.subarray(0, take), received);
    received += take;
  };

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.byteLength) continue;
      const room = maxBytes - received;
      if (value.byteLength > room) {
        append(value, room);
        truncated = true;
        break;
      }
      append(value, value.byteLength);
      if (received === maxBytes) {
        // Cap may coincide with end-of-stream; peek to tell complete from
        // oversized. A body stalling here still fails via the deadline.
        const peek = await reader.read();
        if (!peek.done) truncated = true;
        break;
      }
    }
    if (truncated) {
      reader.cancel().catch(() => {});
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
    try {
      reader.releaseLock();
    } catch {
      // cancel()/read failure may have already released the lock
    }
  }

  if (signal?.aborted) throw bodyAbortError();

  return {
    text: new TextDecoder().decode(buf.subarray(0, received)),
    truncated,
  };
}

export function getPage(ctx: ToolContext) {
  return tool({
    description: `Fetch and extract readable content from a web page. Returns the page title and main text content.

USAGE GUIDANCE:
- Use this tool to read full content from URLs found via web_search
- Fetch CVE details, security advisories, and vulnerability write-ups
- Read documentation, API references, and technical guides
- Extract exploit code, payloads, and proof-of-concept details from security blogs

BEST PRACTICES:
- First use web_search to find relevant URLs, then use get_page to read the full content
- Prefer authoritative sources (NVD, vendor advisories, security researcher blogs)
- For large pages, focus on the most relevant sections
- If content is truncated, the important information is usually near the beginning`,
    inputSchema: getPageInputSchema,
    execute: async ({ url }): Promise<GetPageResponse> => {
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      try {
        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

        const combinedSignal = ctx.abortSignal
          ? AbortSignal.any([ctx.abortSignal, controller.signal])
          : controller.signal;

        // Resolve once, then layer baselines so resolver values still win.
        // Calling bare fetch (not targetFetch) avoids a second resolution
        // pass that would promote baselines above credential headers.
        const resolverSession = resolverSessionFromCtx(ctx);
        const resolved = resolveEffectiveHeaders(resolverSession, url);
        const headers = mergeBaselineHeaders(resolved);

        // biome-ignore lint/style/noRestrictedGlobals: headers fully resolved above; targetFetch would re-resolve
        const response = await fetch(url, {
          method: "GET",
          headers,
          signal: combinedSignal,
          redirect: "follow",
        });

        if (!response.ok) {
          response.body?.cancel().catch(() => {});
          return {
            success: false,
            url,
            error: `Failed to fetch page: ${response.status} ${response.statusText}`,
          };
        }

        const contentType = response.headers.get("content-type") || "";
        if (
          !contentType.includes("text/html") &&
          !contentType.includes("text/plain") &&
          !contentType.includes("application/xhtml")
        ) {
          response.body?.cancel().catch(() => {});
          return {
            success: false,
            url,
            error: `Unsupported content type: ${contentType}. This tool only supports HTML and text pages.`,
          };
        }

        // Deadline covers headers AND body — clearing it at the headers leaves the read unbounded (see readBodyCapped).
        const { text: html, truncated } = await readBodyCapped(
          response,
          MAX_DOWNLOAD_BYTES,
          combinedSignal,
        );
        const title = extractTitle(html);
        let content = extractTextContent(html);

        if (content.length > MAX_CONTENT_LENGTH) {
          content =
            content.substring(0, MAX_CONTENT_LENGTH) +
            "\n\n... (content truncated — page exceeded maximum length)";
        } else if (truncated) {
          content += "\n\n... (page download capped — full page not fetched)";
        }

        return {
          success: true,
          url,
          title,
          content,
        };
      } catch (error: unknown) {
        if (error instanceof Error && error.name === "AbortError") {
          return {
            success: false,
            url,
            error: ctx.abortSignal?.aborted
              ? "Request aborted by user"
              : `Request timeout after ${REQUEST_TIMEOUT / 1000}s`,
          };
        }

        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          url,
          error: `Failed to fetch page: ${errorMsg}`,
        };
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
    },
  });
}

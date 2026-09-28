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
  /** True when the returned content is not the complete page text. */
  contentTruncated?: boolean;
  /** Why the content stopped: preview limit, capture cap, or a failed read. */
  stopReason?: "content-limit" | "byte-cap" | "timeout" | "aborted" | "error";
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

/**
 * Reads up to `maxBytes` into one owned buffer (per-chunk arrays are not a
 * memory bound), cancelling the reader past the cap. Never awaits `cancel()`
 * (it may never settle). A mid-read abort or stream error returns the partial
 * capture plus a stop reason — the caller keeps the extracted partial content
 * instead of discarding it.
 */
type CappedBodyRead = {
  text: string;
  stopReason: "end" | "byte-cap" | "aborted" | "error";
  cause?: unknown;
};

async function readBodyCapped(
  response: Response,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<CappedBodyRead> {
  const captured = (): CappedBodyRead => ({
    text: new TextDecoder().decode(buf.subarray(0, received)),
    stopReason,
    cause,
  });
  // Assigned by the loop below; the closures above read them after it exits.
  let buf = new Uint8Array(0);
  let received = 0;
  let stopReason: CappedBodyRead["stopReason"] = "end";
  let cause: unknown;

  if (signal?.aborted) {
    response.body?.cancel().catch(() => {});
    stopReason = "aborted";
    return captured();
  }
  const body = response.body;
  if (!body) return { text: "", stopReason: "end" };

  const reader = body.getReader();
  // Native-stream arbiter: ONE race, created before the first read. The abort
  // listener resolves the sentinel BEFORE cancelling, and reader.closed
  // stays raw inside the race — a reaction hop would reorder same-turn
  // events. Whichever settles first is the terminal outcome.
  let onAbort: (() => void) | undefined;
  const aborted = signal
    ? new Promise<"aborted">((resolve) => {
        onAbort = () => {
          resolve("aborted");
          reader.cancel().catch(() => {});
        };
        signal.addEventListener("abort", onAbort, { once: true });
      })
    : null;
  const ended = (
    aborted ? Promise.race([reader.closed, aborted]) : reader.closed
  ).then<
    { kind: "end" } | { kind: "aborted" },
    { kind: "error"; cause: unknown }
  >(
    (result) => ({ kind: result === "aborted" ? "aborted" : "end" }),
    (error) => ({ kind: "error", cause: error }),
  );

  buf = new Uint8Array(Math.min(maxBytes, 64 * 1024));

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
      let result: Awaited<ReturnType<typeof reader.read>>;
      try {
        result = await reader.read();
      } catch {
        // The arbiter carries the terminal cause; the read's rejection is
        // the same event seen from the read side. Processing failures below
        // propagate through the finally — they are not stream outcomes.
        break;
      }
      const { done, value } = result;
      if (done) break;
      if (!value?.byteLength) continue;
      const room = maxBytes - received;
      if (value.byteLength > room) {
        append(value, room);
        stopReason = "byte-cap";
        reader.cancel().catch(() => {});
        break;
      }
      append(value, value.byteLength);
      // At the exact cap, keep reading until EOF or a nonempty overflow chunk.
    }
  } finally {
    if (onAbort) signal?.removeEventListener("abort", onAbort);
    // Cancel before release: a processing exception escaping the loop must
    // not leave the stream merely released while the producer keeps pulling.
    reader.cancel().catch(() => {});
    try {
      reader.releaseLock();
    } catch {
      // cancel()/read failure may have already released the lock
    }
  }

  // Cap is explicit and final — never awaited or overwritten by the arbiter.
  if (stopReason === "byte-cap") return captured();

  const end = await ended;
  if (end.kind === "aborted") {
    stopReason = "aborted";
  } else if (end.kind === "error") {
    // Identity, not name: native fetch cancellation rejects the body with
    // the signal's own reason object; an unrelated AbortError-shaped error
    // from an adapter stays an error even once the host signal aborts.
    cause = end.cause;
    stopReason =
      signal?.aborted && end.cause === signal.reason ? "aborted" : "error";
  }
  return captured();
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
        const read = await readBodyCapped(
          response,
          MAX_DOWNLOAD_BYTES,
          combinedSignal,
        );
        // The combined signal cannot say which source fired; the host signal
        // decides between user abort and deadline. undefined = clean end.
        const producerStop: GetPageResponse["stopReason"] =
          read.stopReason === "end"
            ? undefined
            : read.stopReason === "aborted"
              ? ctx.abortSignal?.aborted
                ? "aborted"
                : "timeout"
              : read.stopReason;
        const downloadComplete = producerStop === undefined;
        const title = extractTitle(read.text);
        let content = extractTextContent(read.text);

        // The preview cut applies to the bounded capture on EVERY path — an
        // incomplete download never unlocks an unbounded inline extraction.
        // Preview truncation and producer capture are independent facts: the
        // marker below only says the 50k preview cut happened.
        const previewTruncated = content.length > MAX_CONTENT_LENGTH;
        if (previewTruncated) {
          content =
            content.substring(0, MAX_CONTENT_LENGTH) +
            "\n\n... (content truncated — page exceeded maximum length)";
        }

        // Completion and the producer stop cause come from the read outcome —
        // a preview-truncated partial capture is still a failed capture, and
        // the producer stopReason is never overwritten by 'content-limit'.
        if (!downloadComplete) {
          const incompleteError =
            producerStop === "timeout"
              ? `Request timeout after ${REQUEST_TIMEOUT / 1000}s — partial content extracted`
              : producerStop === "aborted"
                ? "Request aborted by user — partial content extracted"
                : producerStop === "byte-cap"
                  ? "page download capped — full page not fetched"
                  : read.cause instanceof Error
                    ? read.cause.message
                    : String(read.cause);
          content += `\n\n... (INCOMPLETE — ${incompleteError})`;
          return {
            success: false,
            url,
            title,
            content,
            error: incompleteError,
            contentTruncated: true,
            stopReason: producerStop,
          };
        }

        return {
          success: true,
          url,
          title,
          content,
          ...(previewTruncated
            ? { contentTruncated: true, stopReason: "content-limit" }
            : {}),
        };
      } catch (error: unknown) {
        if (error instanceof Error && error.name === "AbortError") {
          return {
            success: false,
            url,
            error: ctx.abortSignal?.aborted
              ? "Request aborted by user"
              : `Request timeout after ${REQUEST_TIMEOUT / 1000}s`,
            contentTruncated: true,
            stopReason: ctx.abortSignal?.aborted ? "aborted" : "timeout",
          };
        }

        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          url,
          error: `Failed to fetch page: ${errorMsg}`,
          contentTruncated: true,
          stopReason: "error",
        };
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
    },
  });
}

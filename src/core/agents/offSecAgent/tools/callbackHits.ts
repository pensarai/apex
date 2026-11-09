import { tool } from "ai";
import { z } from "zod";
import { sessionTestDomains } from "../../../session/testDomains";
import type {
  CallbackBackend,
  CallbackHit,
} from "../../../tools/backends/types";
import type { ToolContext } from "./types";

const MAX_RETURNED_HITS = 25;
const MAX_PATH_CHARS = 512;
const MAX_BODY_CHARS = 256;
const MAX_USER_AGENT_CHARS = 256;
const MAX_MARKER_CHARS = 200;

const NOT_EVIDENCE_OF_ABSENCE =
  "This says nothing about whether the target called back. Report the check as not tested via callback, never as not vulnerable.";

function failure(summary: string) {
  return {
    success: false as const,
    summary,
    artifactPaths: [] as string[],
    nextActions: [NOT_EVIDENCE_OF_ABSENCE],
  };
}

// Header names are case-insensitive, and readers needn't lowercase them.
function headerValue(headers: Record<string, string>, name: string): string {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  return key ? headers[key] : "";
}

function present(hit: CallbackHit) {
  return {
    hitId: hit.id,
    ts: hit.receivedAt,
    method: hit.method,
    path: hit.path.slice(0, MAX_PATH_CHARS),
    ip: hit.sourceIp ?? "",
    userAgent: headerValue(hit.headers, "user-agent").slice(
      0,
      MAX_USER_AGENT_CHARS,
    ),
    body: hit.bodyPreview.slice(0, MAX_BODY_CHARS),
    ...(hit.bodyTruncated || hit.bodyPreview.length > MAX_BODY_CHARS
      ? { bodyTruncated: true }
      : {}),
    ...(hit.late ? { late: true } : {}),
  };
}

/**
 * The host's callbacks reader: on injected backends, or passed on its own
 * (`ctx.callbacks`), whether or not the host also injects backends.
 */
export function callbacksReader(ctx: ToolContext): CallbackBackend | undefined {
  return ctx.backends?.callbacks ?? ctx.callbacks;
}

/** Built only when the session has test domains and the host supplies a callbacks reader (see the registry). */
export function readCallbackHits(ctx: ToolContext) {
  const callbacks = callbacksReader(ctx);
  if (!callbacks) {
    throw new Error(
      "read_callback_hits needs backends.callbacks; the registry should not have built it",
    );
  }
  return tool({
    description: `Read the requests your test domains (${sessionTestDomains(ctx.session).join(", ")}) have received.

Pass the unique path or query marker you embedded in a payload to see only that test's callbacks. A hit proves something fetched the URL; check the source IP, user agent and timing against the payload you sent before treating it as the target. Returns the most recent ${MAX_RETURNED_HITS} matching hits with their hitIds.`,
    inputSchema: z.object({
      marker: z
        .string()
        .min(1)
        .max(MAX_MARKER_CHARS)
        .optional()
        .describe(
          "Substring of the path or query to match, e.g. the marker you put in the payload URL. Omit to read every hit.",
        ),
      toolCallDescription: z
        .string()
        .describe("A concise description of this read"),
    }),
    execute: async ({ marker }) => {
      let result: Awaited<ReturnType<typeof callbacks.readHits>>;
      try {
        result = await callbacks.readHits();
      } catch (error: unknown) {
        return failure(
          `Reading callbacks failed (${error instanceof Error ? error.message : String(error)}). ${NOT_EVIDENCE_OF_ABSENCE}`,
        );
      }
      if ("state" in result) {
        return failure(
          `The callback service is unavailable (${result.reason}). ${NOT_EVIDENCE_OF_ABSENCE}`,
        );
      }

      const matching = marker
        ? result.hits.filter((hit) => hit.path.includes(marker))
        : result.hits;
      const unstored = result.totalHits - result.hits.length;
      const label = marker ? `matching "${marker}"` : "in total";
      return {
        success: true,
        summary: `${matching.length} callback${matching.length === 1 ? "" : "s"} ${label}.${unstored > 0 ? ` ${unstored} more were received past the storage cap and are not readable.` : ""}`,
        data: {
          ...(marker ? { marker } : {}),
          matchingHits: matching.length,
          storedHits: result.hits.length,
          totalHits: result.totalHits,
          recentHits: matching.slice(-MAX_RETURNED_HITS).map(present),
        },
        artifactPaths: [],
        nextActions: [
          "No hit yet is not proof of absence: the target may call back late or not reach the domain. Read again before concluding.",
          "Cite the hitIds of the callbacks you rely on in any finding; the stored hits are the evidence.",
        ],
        truncated: matching.length > MAX_RETURNED_HITS,
      };
    },
  });
}

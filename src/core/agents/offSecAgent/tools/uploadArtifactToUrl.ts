import { tool } from "ai";
import { z } from "zod";
import { readFileSync } from "fs";
import { basename } from "path";
import type { ToolContext } from "./types";
import { hostnameFor } from "./_safetyCaps";

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_INLINE_RESPONSE = 5_000;

export const uploadArtifactToUrlInputSchema = z.object({
  url: z
    .string()
    .url()
    .describe(
      "Target URL to POST/PUT the artifact to (e.g. https://target.example/api/upload).",
    ),
  artifactPath: z
    .string()
    .describe(
      "Absolute path to the artifact on disk (typically /work/artifact.* staged by the test-case workflow).",
    ),
  fieldName: z
    .string()
    .default("file")
    .describe(
      "The form-field name for the file part. Common values: 'file', 'upload', 'attachment'. Check the target's API docs.",
    ),
  additionalFields: z
    .record(z.string(), z.string())
    .optional()
    .describe(
      'Extra multipart form-data fields (text, not files) sent alongside the file — e.g. {"description": "malicious test", "csrf_token": "..."}.',
    ),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe(
      "Extra HTTP headers to merge into the request (on top of any default auth headers set by the workflow).",
    ),
  method: z
    .enum(["POST", "PUT"])
    .default("POST")
    .describe("HTTP method. POST for typical upload endpoints; PUT for REST-style upserts."),
  timeoutMs: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(`Request timeout in ms (default ${DEFAULT_TIMEOUT_MS}).`),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Uploading EICAR zip to /api/upload to test AV rejection')",
    ),
});

export type UploadArtifactToUrlInput = z.infer<
  typeof uploadArtifactToUrlInputSchema
>;

export type UploadArtifactToUrlResult = {
  success: boolean;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  body?: string;
  bodyTruncated?: boolean;
  redirected?: boolean;
  url?: string;
  durationMs: number;
  error?: string;
};

function truncate(body: string): {
  body: string;
  bodyTruncated: boolean;
} {
  if (body.length <= MAX_INLINE_RESPONSE) return { body, bodyTruncated: false };
  return {
    body: `${body.slice(0, MAX_INLINE_RESPONSE)}...\n\n(truncated from ${body.length}B)`,
    bodyTruncated: true,
  };
}

function emitAlertOnRejection(
  ctx: ToolContext,
  status: number,
  url: string,
  fieldName: string,
): void {
  // Treat 4xx as "target infra caught the upload" — the valuable signal
  // for a malicious-upload test. 5xx is a server error (noise).
  if (status >= 400 && status < 500) {
    ctx.eventBus?.emit("detection_event", {
      kind: "alert_raised",
      severity: "medium",
      source: "rule-engine",
      summary: `Target rejected upload: HTTP ${status} from ${url}`,
      data: {
        url,
        status,
        fieldName,
        interpretation:
          "Target infra (WAF/AV/validation) blocked the upload. This is the success signal for a malicious-upload test.",
      },
    });
  }
}

function emitEgress(
  ctx: ToolContext,
  url: string,
  method: string,
  status: number | undefined,
): void {
  try {
    ctx.eventBus?.emit("detection_event", {
      kind: "network_egress",
      severity: "low",
      source: "apex",
      summary: `Outbound ${method} to ${new URL(url).hostname} (status=${status ?? "?"})`,
      data: { url, method, status, source: "upload_artifact_to_url" },
    });
  } catch {
    /* URL parsing can fail — swallow */
  }
}

export function uploadArtifactToUrl(ctx: ToolContext) {
  return tool({
    description: `Upload a file from the sandbox filesystem to a target URL via multipart/form-data POST (or PUT).

This is the canonical tool for "send this malicious file to the customer's
upload endpoint and see how the infra handles it" scenarios. Pre-verify the
artifact's contents with \`check_file_signature\` first when you need to
confirm it contains what you claim it does (e.g. real EICAR vs filename-only).

Auto-emits:
  • \`network_egress\` for every outbound request (always).
  • \`alert_raised\` if the target returns 4xx — treat that as evidence the
    target's WAF/AV/validation correctly rejected the upload.

Does NOT auto-emit when the target accepts (2xx) — interpret that yourself:
for a known-bad file, a 2xx is usually the FAILURE signal (target's
infra did not catch the malicious content). Emit \`alert_raised\` manually
in that case via \`emit_detection_event\` with the interpretation spelled out.

Respects the per-run safety caps and merges \`defaultHeaders\` (target auth)
from the tool context.`,
    inputSchema: uploadArtifactToUrlInputSchema,
    execute: async (input): Promise<UploadArtifactToUrlResult> => {
      const startedAt = Date.now();
      const url = input.url;
      const host = hostnameFor(url);

      // Safety caps
      if (ctx.safetyCaps) {
        const v = await ctx.safetyCaps.checkAndConsume(host);
        if (v) {
          return {
            success: false,
            durationMs: Date.now() - startedAt,
            error: `Safety cap exceeded: ${v.message}`,
          };
        }
      }

      let bytes: Buffer;
      try {
        bytes = readFileSync(input.artifactPath);
      } catch (err) {
        return {
          success: false,
          durationMs: Date.now() - startedAt,
          error: `Failed to read artifact ${input.artifactPath}: ${err instanceof Error ? err.message : String(err)}`,
        };
      }

      try {
        const form = new FormData();
        const blob = new Blob([new Uint8Array(bytes)]);
        form.append(input.fieldName, blob, basename(input.artifactPath));
        for (const [k, v] of Object.entries(input.additionalFields ?? {})) {
          form.append(k, v);
        }

        const mergedHeaders: Record<string, string> = {
          ...(ctx.defaultHeaders ?? {}),
          ...(input.headers ?? {}),
        };

        const controller = new AbortController();
        const timer = setTimeout(
          () => controller.abort(),
          input.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        );

        try {
          const resp = await fetch(url, {
            method: input.method,
            headers: mergedHeaders,
            body: form,
            signal: controller.signal,
          });
          clearTimeout(timer);
          const respText = await resp.text();
          const { body, bodyTruncated } = truncate(respText);
          const headers: Record<string, string> = {};
          resp.headers.forEach((value, key) => {
            headers[key] = value;
          });

          emitEgress(ctx, url, input.method, resp.status);
          emitAlertOnRejection(ctx, resp.status, url, input.fieldName);

          return {
            success: true,
            status: resp.status,
            statusText: resp.statusText,
            headers,
            body,
            bodyTruncated,
            redirected: resp.redirected,
            url: resp.url,
            durationMs: Date.now() - startedAt,
          };
        } finally {
          clearTimeout(timer);
        }
      } catch (error) {
        emitEgress(ctx, url, input.method, undefined);
        return {
          success: false,
          durationMs: Date.now() - startedAt,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

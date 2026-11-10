/**
 * HTTP PoCs: a finding's proof written as a list of requests instead of a
 * script. Only each request's URL is a request target, so a URL sent as data
 * (an SSRF, open-redirect or webhook payload) is never mistaken for one. The
 * requests are checked like `http_request` calls, then written out as a bash
 * curl script, which runs and is stored like any other PoC.
 */

import { z } from "zod";
import { assertHttpActionAllowed } from "./destructiveGuard";
import { assertUrlInScope } from "./scopeGuard";
import type { ToolContext } from "./types";

export const httpPocRequestSchema = z.object({
  method: z.string().describe("HTTP method, e.g. GET or POST"),
  url: z
    .string()
    .describe(
      "Request URL on an in-scope target. This is the only field checked as a request target",
    ),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe("Request headers. Values are sent as written"),
  body: z
    .string()
    .optional()
    .describe(
      "Request body, sent byte for byte. URLs in the body are payload data, not request targets",
    ),
  expectStatus: z
    .number()
    .int()
    .optional()
    .describe("HTTP status the response must have"),
  expectBodyContains: z
    .string()
    .min(1)
    .optional()
    .describe("Text the response body must contain"),
});

export type HttpPocRequest = z.infer<typeof httpPocRequestSchema>;

/** The request list cannot be turned into a runnable PoC. */
export class HttpPocError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HttpPocError";
  }
}

const MAX_REQUESTS = 10;
const RESPONSE_PRINT_BYTES = 20_000;
const METHOD = /^[A-Za-z]+$/;
// RFC 9110 token characters.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function requireText(value: string, field: string): void {
  if (value.includes("\0")) {
    throw new HttpPocError(`${field} contains a NUL byte.`);
  }
}

// Canonical form, so curl requests exactly the host the scope check approved.
function canonicalUrl(raw: string, index: number): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new HttpPocError(`Request ${index}: "${raw}" is not a valid URL.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new HttpPocError(`Request ${index}: only http and https URLs run.`);
  }
  return url.href;
}

function requestLines(request: HttpPocRequest, index: number): string[] {
  if (!METHOD.test(request.method)) {
    throw new HttpPocError(
      `Request ${index}: "${request.method}" is not an HTTP method.`,
    );
  }
  const method = request.method.toUpperCase();
  const url = canonicalUrl(request.url, index);

  const curl = [
    "curl -q -sS --proto '=http,https' --max-time 30",
    `-o "$body_file" -w '%{http_code}'`,
    `-X ${shellQuote(method)}`,
  ];
  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (!HEADER_NAME.test(name)) {
      throw new HttpPocError(
        `Request ${index}: "${name}" is not a valid header name.`,
      );
    }
    if (/[\r\n\0]/.test(value)) {
      throw new HttpPocError(
        `Request ${index}: header ${name} contains a line break or NUL byte.`,
      );
    }
    curl.push(`-H ${shellQuote(`${name}: ${value}`)}`);
  }

  let command: string;
  if (request.body === undefined) {
    command = curl.join(" ");
  } else {
    requireText(request.body, `Request ${index} body`);
    // From stdin, so a body that starts with @ is sent, not read as a file.
    curl.push("--data-binary @-");
    command = `printf '%s' ${shellQuote(request.body)} | ${curl.join(" ")}`;
  }
  command += ` --url ${shellQuote(url)}`;

  const lines = [
    `echo ${shellQuote(`== ${index}. ${method} ${url}`)}`,
    `status=$(${command}) || fail=1`,
    'echo "status: $status"',
    `head -c ${RESPONSE_PRINT_BYTES} "$body_file"; echo`,
  ];
  if (request.expectStatus !== undefined) {
    const expected = String(request.expectStatus);
    lines.push(
      `[ "$status" = ${shellQuote(expected)} ] || { echo ${shellQuote(`FAIL: expected status ${expected}`)}; fail=1; }`,
    );
  }
  if (request.expectBodyContains !== undefined) {
    requireText(request.expectBodyContains, `Request ${index} expected text`);
    lines.push(
      `grep -qF -- ${shellQuote(request.expectBodyContains)} "$body_file" || { echo ${shellQuote("FAIL: response does not contain the expected text")}; fail=1; }`,
    );
  }
  return lines;
}

/**
 * Check an HTTP PoC's requests and write them as a bash script that exits 0
 * only when every expectation holds. Throws `ScopeViolationError` or
 * `DestructiveActionError` as `http_request` would, and `HttpPocError` for a
 * request list that can't run.
 */
export function buildHttpPocScript(
  requests: HttpPocRequest[] | undefined,
  ctx: ToolContext,
): string {
  if (!requests || requests.length === 0) {
    throw new HttpPocError(
      'pocType "http" needs at least one pocRequests entry.',
    );
  }
  if (requests.length > MAX_REQUESTS) {
    throw new HttpPocError(
      `pocRequests has ${requests.length} requests; the limit is ${MAX_REQUESTS}.`,
    );
  }
  if (
    !requests.some(
      (r) => r.expectStatus !== undefined || r.expectBodyContains !== undefined,
    )
  ) {
    throw new HttpPocError(
      "Set expectStatus or expectBodyContains on at least one request, so the PoC can tell success from failure.",
    );
  }

  for (const [i, request] of requests.entries()) {
    const url = canonicalUrl(request.url, i + 1);
    assertUrlInScope(url, ctx);
    assertHttpActionAllowed(
      {
        method: request.method,
        url,
        body: request.body,
        headers: request.headers,
      },
      ctx,
    );
  }

  return [
    "#!/bin/bash",
    "set -u",
    "fail=0",
    "body_file=$(mktemp)",
    `trap 'rm -f "$body_file"' EXIT`,
    "",
    ...requests.flatMap((request, i) => [...requestLines(request, i + 1), ""]),
    'exit "$fail"',
    "",
  ].join("\n");
}

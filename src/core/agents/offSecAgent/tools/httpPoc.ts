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
  headers: z.record(z.string(), z.string()).optional().describe(
    // biome-ignore lint/suspicious/noTemplateCurlyInString: documents shell variable syntax
    "Request headers. $NAME or ${NAME} in a value is replaced with that environment variable when the POC runs; other text is sent as written",
  ),
  body: z.string().optional().describe(
    // biome-ignore lint/suspicious/noTemplateCurlyInString: documents shell variable syntax
    "Request body. URLs in the body are payload data, not request targets. $NAME or ${NAME} is replaced with that environment variable when the POC runs; other text is sent byte for byte",
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
    .describe("One line of text the response body must contain"),
  expectHeaderContains: z
    .string()
    .min(1)
    .optional()
    .describe(
      "One line of text the response headers must contain, ignoring case, e.g. a redirect's Location: http://169.254.169.254/",
    ),
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
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const HEADER_PRINT_BYTES = 8_000;
// RFC 9110 token characters, for methods and header names.
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const ENV_REFERENCE = /\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))/g;

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

// Double-quoted, so the run's credential variables expand when the POC runs
// and the stored script never holds their values. Any other `$`, such as a
// NoSQL operator, stays literal.
function shellValue(value: string, envNames: ReadonlySet<string>): string {
  const escapeText = (text: string) => text.replace(/[\\"$`]/g, "\\$&");
  let quoted = "";
  let last = 0;
  for (const match of value.matchAll(ENV_REFERENCE)) {
    const name = match[1] ?? match[2];
    if (!envNames.has(name)) continue;
    quoted += `${escapeText(value.slice(last, match.index))}\${${name}}`;
    last = match.index + match[0].length;
  }
  return `"${quoted}${escapeText(value.slice(last))}"`;
}

// The value the POC will send, for checks that must see what goes on the wire.
function expandEnv(
  value: string,
  env: Readonly<Record<string, string>>,
): string {
  return value.replace(ENV_REFERENCE, (reference, braced, bare) => {
    const name = braced ?? bare;
    return Object.hasOwn(env, name) ? env[name] : reference;
  });
}

function requireText(value: string, field: string): void {
  if (value.includes("\0")) {
    throw new HttpPocError(`${field} contains a NUL byte.`);
  }
}

function requireOneLine(value: string, field: string, index: number): void {
  // grep reads each line as its own pattern and passes if any one matches.
  if (/[\r\n\0]/.test(value)) {
    throw new HttpPocError(
      `Request ${index}: ${field} must be one line of text, with no line breaks or NUL bytes.`,
    );
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

function requestLines(
  request: HttpPocRequest,
  index: number,
  envNames: ReadonlySet<string>,
): string[] {
  if (!TOKEN.test(request.method)) {
    throw new HttpPocError(
      `Request ${index}: "${request.method}" is not an HTTP method.`,
    );
  }
  const method = request.method.toUpperCase();
  const url = canonicalUrl(request.url, index);

  const curl = [
    // -g: [] and {} in the URL are literal, not curl globs.
    "curl -q -g -sS --proto '=http,https' --max-time 30",
    // Only the target's headers, never a proxy's CONNECT response.
    `--suppress-connect-headers -D "$header_file" -o "$body_file" -w '%{http_code}'`,
    // -X HEAD changes only the method; curl would still wait for a body.
    // HEAD downloads nothing, and the cap would test its Content-Length.
    method === "HEAD"
      ? "-I"
      : `-X ${shellQuote(method)} --max-filesize ${MAX_RESPONSE_BYTES}`,
  ];
  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (!TOKEN.test(name)) {
      throw new HttpPocError(
        `Request ${index}: "${name}" is not a valid header name.`,
      );
    }
    if (/[\r\n\0]/.test(value)) {
      throw new HttpPocError(
        `Request ${index}: header ${name} contains a line break or NUL byte.`,
      );
    }
    // curl drops "Name: " but sends "Name;" as a header with an empty value.
    curl.push(
      value === ""
        ? `-H ${shellQuote(`${name};`)}`
        : `-H ${shellValue(`${name}: ${value}`, envNames)}`,
    );
  }

  let command: string;
  if (request.body === undefined) {
    command = curl.join(" ");
  } else {
    requireText(request.body, `Request ${index} body`);
    // From stdin, so a body that starts with @ is sent, not read as a file.
    curl.push("--data-binary @-");
    command = `printf '%s' ${shellValue(request.body, envNames)} | ${curl.join(" ")}`;
  }
  command += ` --url ${shellQuote(url)}`;

  const lines = [
    `echo ${shellQuote(`== ${index}. ${method} ${url}`)}`,
    `status=$(${command}) || fail=1`,
    'echo "status: $status"',
    `head -c ${HEADER_PRINT_BYTES} "$header_file"`,
    `head -c ${RESPONSE_PRINT_BYTES} "$body_file"; echo`,
  ];
  if (request.expectStatus !== undefined) {
    const expected = String(request.expectStatus);
    lines.push(
      `[ "$status" = ${shellQuote(expected)} ] || { echo ${shellQuote(`FAIL: expected status ${expected}`)}; fail=1; }`,
    );
  }
  if (request.expectBodyContains !== undefined) {
    // curl -I writes the headers where the body would go.
    if (method === "HEAD") {
      throw new HttpPocError(
        `Request ${index}: a HEAD response has no body; use expectHeaderContains or expectStatus.`,
      );
    }
    requireOneLine(request.expectBodyContains, "expectBodyContains", index);
    lines.push(
      `grep -qF -- ${shellQuote(request.expectBodyContains)} "$body_file" || { echo ${shellQuote("FAIL: response does not contain the expected text")}; fail=1; }`,
    );
  }
  if (request.expectHeaderContains !== undefined) {
    requireOneLine(request.expectHeaderContains, "expectHeaderContains", index);
    lines.push(
      `grep -qiF -- ${shellQuote(request.expectHeaderContains)} "$header_file" || { echo ${shellQuote("FAIL: response headers do not contain the expected text")}; fail=1; }`,
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
      (r) =>
        r.expectStatus !== undefined ||
        r.expectBodyContains !== undefined ||
        r.expectHeaderContains !== undefined,
    )
  ) {
    throw new HttpPocError(
      "Set expectStatus, expectBodyContains or expectHeaderContains on at least one request, so the PoC can tell success from failure.",
    );
  }

  const env = ctx.environmentVariables ?? {};
  for (const [i, request] of requests.entries()) {
    const url = canonicalUrl(request.url, i + 1);
    assertUrlInScope(url, ctx);
    const headers =
      request.headers &&
      Object.fromEntries(
        Object.entries(request.headers).map(([name, value]) => [
          name,
          expandEnv(value, env),
        ]),
      );
    // A line break in an expanded value would send headers nobody declared.
    for (const [name, value] of Object.entries(headers ?? {})) {
      if (/[\r\n\0]/.test(value)) {
        throw new HttpPocError(
          `Request ${i + 1}: header ${name} contains a line break or NUL byte once its environment variables are expanded.`,
        );
      }
    }
    // Classified on the expanded values the request will actually carry.
    assertHttpActionAllowed(
      {
        method: request.method,
        url,
        body:
          request.body === undefined ? undefined : expandEnv(request.body, env),
        headers,
      },
      ctx,
    );
  }

  const envNames = new Set(Object.keys(env));
  return [
    "#!/bin/bash",
    "set -u",
    "fail=0",
    "body_file=$(mktemp)",
    "header_file=$(mktemp)",
    `trap 'rm -f "$body_file" "$header_file"' EXIT`,
    "",
    ...requests.flatMap((request, i) => [
      ...requestLines(request, i + 1, envNames),
      "",
    ]),
    'exit "$fail"',
    "",
  ].join("\n");
}

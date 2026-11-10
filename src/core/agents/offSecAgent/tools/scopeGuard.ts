/**
 * Scope guard — enforces domain-level scoping for tool calls.
 *
 * When a target is configured, all outbound HTTP requests and commands
 * are checked to ensure they only hit allowed domains (hostname match).
 * Endpoint paths are intentionally NOT checked — the guard only restricts
 * the domain, not which paths the agent visits on that domain.
 *
 * An explicit `scopeConstraints.allowedHosts` list is authoritative. Without
 * one, exact hosts are derived from `ctx.target` and `session.targets`.
 * Subdomains are permitted only by an explicit `*.example.com` entry.
 */

import { parseTargetUrl } from "../../../../util/url";
import type { ResolverSession } from "../../../http/targetHeaders";
import {
  getRegistrableDomain,
  getSessionAllowedHosts,
  getSessionAllowedPorts,
  getUrlPort,
  isCallbackHost,
  isHostInScope,
} from "../../../http/targetScope";
import { callbackDomains } from "../../../tools/backends/callbacks";
import type { ToolContext } from "./types";

export { getRegistrableDomain };

export class ScopeViolationError extends Error {
  constructor(
    public readonly hostname: string,
    public readonly allowedHosts: string[],
    public readonly port?: number,
    public readonly allowedPorts: number[] = [],
  ) {
    super(
      port !== undefined && allowedPorts.length > 0
        ? `Scope violation: port ${port} on "${hostname}" is not in the list of allowed target ports [${allowedPorts.join(", ")}].`
        : `Scope violation: "${hostname}" is not in the list of allowed target domains [${allowedHosts.join(", ")}]. ` +
            `Only exact hosts and explicit wildcard grants are permitted.`,
    );
    this.name = "ScopeViolationError";
  }
}

// Fold `ctx.target` into the resolver's `targets` view so sub-agent
// commands (where `ctx.target` isn't in `session.targets`) don't get
// classified as out-of-scope and silently dropped from header resolution.
export function resolverSessionFromCtx(ctx: ToolContext): ResolverSession {
  const existing = ctx.session.targets ?? [];
  const targets =
    ctx.target && !existing.includes(ctx.target)
      ? [...existing, ctx.target]
      : existing;
  const domains = callbackDomains(ctx);
  if (targets === existing && domains.length === 0) return ctx.session;
  return {
    ...ctx.session,
    targets,
    ...(domains.length > 0 ? { callbackDomains: domains } : {}),
  };
}

/**
 * Build the set of allowed hostnames from the tool context.
 * Returns an empty array when no scope is configured (= no enforcement).
 */
export function getAllowedHosts(ctx: ToolContext): string[] {
  return getSessionAllowedHosts(resolverSessionFromCtx(ctx));
}

export function getAllowedPorts(ctx: ToolContext): number[] {
  return getSessionAllowedPorts(resolverSessionFromCtx(ctx));
}

/**
 * Check whether `hostname` is within the allowed scope.
 *
 * Matching rules:
 *  - Exact match: `example.com` matches `example.com`
 *  - Subdomain match: `api.example.com` matches allowed `example.com`
 *  - IP addresses: matched exactly (no subdomain logic)
 *  - Case-insensitive on both sides
 */
export function isHostAllowed(
  hostname: string,
  allowedHosts: string[],
): boolean {
  return isHostInScope(hostname, allowedHosts);
}

function strictScope(ctx: ToolContext): boolean {
  return ctx.session.config?.scopeConstraints?.strictScope === true;
}

/**
 * Extract the hostname from a URL string. Returns `null` for unparseable URLs.
 */
export function extractHostname(url: string): string | null {
  const parsed = parseTargetUrl(url);
  return parsed ? parsed.hostname.toLowerCase() : null;
}

/**
 * Assert that a URL targets an allowed domain. Throws `ScopeViolationError`
 * if the hostname is out of scope or the URL is unparseable (fail-closed).
 *
 * No-op when no scope is configured (no target, no allowedHosts).
 */
export function assertUrlInScope(url: string, ctx: ToolContext): void {
  const allowedHosts = getAllowedHosts(ctx);
  const allowedPorts = getAllowedPorts(ctx);
  if (
    allowedHosts.length === 0 &&
    allowedPorts.length === 0 &&
    !strictScope(ctx)
  ) {
    return;
  }

  const hostname = extractHostname(url);
  if (!hostname) {
    throw new ScopeViolationError(url, allowedHosts);
  }

  if (!isHostAllowed(hostname, allowedHosts)) {
    throw new ScopeViolationError(hostname, allowedHosts);
  }

  const port = getUrlPort(url);
  if (
    allowedPorts.length > 0 &&
    (port === null || !allowedPorts.includes(port))
  ) {
    throw new ScopeViolationError(
      hostname,
      allowedHosts,
      port ?? undefined,
      allowedPorts,
    );
  }
}

/**
 * {@link assertUrlInScope} for a plain request destination, which may also be
 * one of the session's test domains. Never use it where the URL becomes a
 * target (findings, subagent targets, auth flows): test domains are not.
 */
export function assertRequestInScope(url: string, ctx: ToolContext): void {
  const hostname = extractHostname(url);
  if (hostname && isCallbackHost(hostname, resolverSessionFromCtx(ctx))) return;
  assertUrlInScope(url, ctx);
}

/**
 * Assert that a finding's `endpoint` is within the engagement scope before it
 * enters the shared findings registry. Defense in depth: a routing error must
 * not be able to write infrastructure findings (e.g. against `127.0.0.1`) into
 * the customer registry.
 *
 * Only enforced when the endpoint carries an explicit http(s) authority. Bare
 * paths (e.g. `/api/users`) have no host — they are implicitly the in-scope
 * target — so they are allowed. Throws `ScopeViolationError` for an
 * out-of-scope host. No-op when no scope is configured.
 */
export function assertFindingEndpointInScope(
  endpoint: string,
  ctx: ToolContext,
): void {
  const allowedHosts = getAllowedHosts(ctx);
  const allowedPorts = getAllowedPorts(ctx);
  if (
    allowedHosts.length === 0 &&
    allowedPorts.length === 0 &&
    !strictScope(ctx)
  ) {
    return;
  }

  // Only absolute http(s) URLs name their own host; anything else (a path,
  // "host:port", a scheme-less token) is treated as relative to the in-scope
  // target and left to the existing deterministic target boundary.
  if (!/^https?:\/\//i.test(endpoint.trim())) return;
  assertUrlInScope(endpoint, ctx);
}

const URL_PATTERN = /https?:\/\/[^\s"'`;|&)<>]+/gi;

// A URL that is a later parameter value of another URL, as in
// `https://app/fetch?a=1&url=http://169.254.169.254/`. The outer URL is still
// checked; nothing between it and the nested URL can end the word.
const NESTED_QUERY_VALUE =
  /https?:\/\/[\w.~%+,/:@[\]-]+\?[\w.~%+=&,/:-]*&[\w.~%+-]*=$/;

const CURL_PAYLOAD_FLAGS = new Set([
  "-d",
  "--data",
  "--data-raw",
  "--data-binary",
  "--data-urlencode",
  "--json",
  "-H",
  "--header",
  "-F",
  "--form",
]);

// What a payload URL may follow inside a curl body or header value: a JSON
// string, a form value or a header value. With one in front, the value never
// parses as a URL, so it is not requested even if curl reads it as one.
const PAYLOAD_URL_PREFIX = /(?:"|=|:[ \t]*)$/;

interface Word {
  start: number;
  end: number;
}

// The words of every line that uses nothing but plain words and quoting. Lines
// with operators, substitutions, variables, redirects or braces are left out.
function plainLines(command: string): Word[][] {
  const lines: Word[][] = [];
  let words: Word[] = [];
  let word: Word | null = null;
  let plain = true;
  let quote: string | null = null;

  const endWord = () => {
    if (word) words.push(word);
    word = null;
  };
  const endLine = () => {
    endWord();
    if (plain && words.length > 0) lines.push(words);
    words = [];
    plain = true;
  };

  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (quote === '"' && /[$`\\]/.test(c)) plain = false;
    } else if (c === "\\" && command[i + 1] === "\n") {
      endWord();
      i++;
      continue;
    } else if (c === "\n") {
      endLine();
      continue;
    } else if (c === " " || c === "\t" || c === "\r") {
      endWord();
      continue;
    } else if (c === "'" || c === '"') {
      quote = c;
    } else if (/[;|&<>(){}$`\\#]/.test(c)) {
      plain = false;
    }
    if (word) word.end = i + 1;
    else word = { start: i, end: i + 1 };
  }
  if (quote) plain = false;
  endLine();
  return lines;
}

// The inside of each fully quoted value given to a curl body or header flag.
function curlPayloadRanges(command: string): Array<[number, number]> {
  const text = (w: Word) => command.slice(w.start, w.end);
  const ranges: Array<[number, number]> = [];
  for (const words of plainLines(command)) {
    if (text(words[0]) !== "curl") continue;
    for (let i = 1; i < words.length - 1; i++) {
      if (!CURL_PAYLOAD_FLAGS.has(text(words[i]))) continue;
      const value = text(words[i + 1]);
      const q = value[0];
      if (
        (q === "'" || q === '"') &&
        value.length >= 2 &&
        value.endsWith(q) &&
        !value.slice(1, -1).includes(q)
      ) {
        ranges.push([words[i + 1].start + 1, words[i + 1].end - 1]);
      }
    }
  }
  return ranges;
}

// Blank out URLs the command sends as data rather than requests: SSRF,
// open-redirect and webhook payloads. Everything else is still a target.
function maskPayloadUrls(command: string): string {
  const payloads = curlPayloadRanges(command);
  let masked = command;
  for (const match of command.matchAll(URL_PATTERN)) {
    const at = match.index;
    const inPayload = payloads.some(
      ([start, end]) =>
        at > start &&
        at < end &&
        PAYLOAD_URL_PREFIX.test(command.slice(start, at)),
    );
    const nested = NESTED_QUERY_VALUE.test(
      command.slice(Math.max(0, at - 2048), at),
    );
    if (inPayload || nested) {
      masked =
        masked.slice(0, at) +
        "_".repeat(match[0].length) +
        masked.slice(at + match[0].length);
    }
  }
  return masked;
}

/**
 * Extract URLs and hostnames from a shell command string.
 *
 * Looks for:
 *  - Explicit URLs: http(s)://host...
 *  - Hostnames after common networking tools (curl, wget, nmap, etc.)
 *
 * Payload URLs (see `maskPayloadUrls`) are not targets.
 */
export function extractHostsFromCommand(rawCommand: string): string[] {
  const hosts = new Set<string>();
  const command = maskPayloadUrls(rawCommand);

  // 1. Extract all http(s) URLs
  for (const match of command.matchAll(URL_PATTERN)) {
    const hostname = extractHostname(match[0]);
    if (hostname) hosts.add(hostname);
  }

  // 2. Extract hostnames after common networking tools.
  //    Pattern: <tool> [flags...] <hostname-or-url> [more args...]
  //    We look for bare hostnames (not starting with -) after the tool name.
  const networkTools = [
    "curl",
    "wget",
    "nmap",
    "nikto",
    "gobuster",
    "ffuf",
    "sqlmap",
    "hydra",
    "dirb",
    "wfuzz",
    "nc",
    "ncat",
    "netcat",
    "openssl",
    "sslscan",
    "testssl",
    "masscan",
    "dig",
    "host",
    "whois",
    "ping",
    "traceroute",
    "ssh",
    "telnet",
    "nuclei",
    "httpx",
    "subfinder",
    "amass",
    "feroxbuster",
  ];

  const toolPattern = new RegExp(
    `(?:^|[;&|]|\\$\\()\\s*(?:sudo\\s+)?(?:timeout\\s+\\S+\\s+)?` +
      `(?:${networkTools.join("|")})\\s+` +
      `([^;&|]+)`,
    "gi",
  );

  // Flags whose next token is a non-host value (file path, script name,
  // wordlist, output file, etc.) and should be skipped during extraction.
  const flagsWithValueArg = new Set([
    "-o",
    "-oN",
    "-oX",
    "-oG",
    "-oA",
    "--output",
    "-w",
    "--wordlist",
    "--script",
    "-iL",
    "-iR",
    "--excludefile",
    "--exclude",
    "-e",
    "--extensions",
    "-x",
    "-b",
    "--cookie",
    "-d",
    "--data",
    "-H",
    "--header",
    "-A",
    "--user-agent",
    "-T",
    "--upload-file",
    "-F",
    "--form",
    "-u",
    "--user",
    "--proxy",
    "-L",
    "--log",
    "--rate",
    "-t",
    "--threads",
    "-c",
    "--config",
    "-r",
    "--report",
    "-D",
    "--delay",
    "--timeout",
  ]);

  for (const match of command.matchAll(toolPattern)) {
    const argsStr = match[1];
    const tokens = argsStr.split(/\s+/);
    let skipNext = false;
    for (const token of tokens) {
      if (!token) continue;

      if (skipNext) {
        skipNext = false;
        continue;
      }

      // Check if this flag takes a value argument (skip the next token)
      if (token.startsWith("-")) {
        // Handle --flag=value (no skip needed, value is attached)
        if (!token.includes("=") && flagsWithValueArg.has(token)) {
          skipNext = true;
        }
        continue;
      }
      if (token.startsWith("/")) continue;

      // Could be a URL
      if (token.match(/^https?:\/\//i)) {
        const h = extractHostname(token);
        if (h) hosts.add(h);
        continue;
      }

      // Could be a hostname or IP (with optional :port)
      const hostPortMatch = token.match(
        /^([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?$/,
      );
      if (hostPortMatch) {
        hosts.add(hostPortMatch[1].toLowerCase());
      }
    }
  }

  return [...hosts];
}

/**
 * Assert that a shell command only targets allowed domains.
 *
 * Extracts hostnames from the command string and checks each against
 * the scope. Throws `ScopeViolationError` on the first violation.
 *
 * No-op when no scope is configured.
 */
export function assertCommandInScope(command: string, ctx: ToolContext): void {
  const allowedHosts = getAllowedHosts(ctx);
  if (allowedHosts.length === 0 && !strictScope(ctx)) return;

  const commandHosts = extractHostsFromCommand(command);
  const scope = resolverSessionFromCtx(ctx);

  for (const hostname of commandHosts) {
    // Test domains appear in payloads (and self-checks) without being targets.
    if (isCallbackHost(hostname, scope)) continue;
    if (!isHostAllowed(hostname, allowedHosts)) {
      throw new ScopeViolationError(hostname, allowedHosts);
    }
  }
}

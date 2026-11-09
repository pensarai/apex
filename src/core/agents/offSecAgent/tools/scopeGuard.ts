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
  isHostInScope,
} from "../../../http/targetScope";
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
  if (!ctx.target) return ctx.session;
  const existing = ctx.session.targets ?? [];
  if (existing.includes(ctx.target)) return ctx.session;
  return {
    ...ctx.session,
    targets: [...existing, ctx.target],
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

// Short flags take attached or separate values and mean data/form/header only
// to curl (wget's -d/-F/-H take no value).
const SHELL_PAYLOAD_ARG =
  /(?:^|\s)(?:(-[dFH])(?:\s|\\\r?\n)*|(?:--data(?:-raw|-binary|-urlencode|-ascii)?|--json|--form(?:-string)?|--header|--post-data|--body-data)(?:(?:\s|\\\r?\n)+|=))('[^']*'|"(?:\\.|[^"\\])*"|\S+)/g;

const STRING_OPEN = String.raw`(?:[rRbBfFuU]{1,2})?\\?["'\x60]`;
const PARAM_VALUE_PREFIX = /[?&'"](?!-)[\w.%[\]-]*=$/;
const OBJECT_VALUE_PREFIX = new RegExp(
  String.raw`(?:\\?["']([\w.-]+)\\?["']|[{,]\s*(?!lambda\b)([A-Za-z_$][\w$]*))[ \t]*:[ \t]*${STRING_OPEN}$`,
);
// Keys a client library reads as where to send the request (axios/fetch
// config, `requests.request(**{...})`, proxy maps).
const REQUEST_TARGET_KEY =
  /^(?:url|uri|href|endpoint|base_?url|host|hostname|https?|all)$/i;
const BODY_NAMES = "json|data|body|params|form|files";
const BODY_KEY_PREFIX = new RegExp(
  String.raw`\b["']?(?:${BODY_NAMES})["']?\s*:\s*$`,
  "i",
);
const BODY_ENCODER_PREFIX = /\b(?:JSON\.stringify|json\.dumps|urlencode)\s*$/;
const ASSIGNMENT_PREFIX = /(?:^|[^\w$.=!<>])([A-Za-z_$][\w$]*)\s*=\s*$/;
const FOR_IN_PREFIX = /\bfor\s+([A-Za-z_]\w*)\s+in\s*$/;

function lastHttpToolOnLine(command: string, index: number): string | null {
  const lines = command
    .slice(0, index)
    .replace(/\\\r?\n/g, " ")
    .split("\n");
  const tools = [...lines[lines.length - 1].matchAll(/\b(curl|wget)\b/g)];
  return tools.length > 0 ? tools[tools.length - 1][1] : null;
}

function shellPayloadRanges(command: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  for (const match of command.matchAll(SHELL_PAYLOAD_ARG)) {
    if (match[1] && lastHttpToolOnLine(command, match.index) !== "curl") {
      continue;
    }
    const end = match.index + match[0].length;
    ranges.push([end - match[2].length, end]);
  }
  return ranges;
}

function* unmatchedOpeners(
  command: string,
  index: number,
): Generator<{ char: string; at: number }> {
  let depth = 0;
  for (let i = index - 1; i >= Math.max(0, index - 2000); i--) {
    const ch = command[i];
    if (ch === "}" || ch === "]" || ch === ")") depth++;
    else if (ch === "{" || ch === "[" || ch === "(") {
      if (depth > 0) depth--;
      else yield { char: ch, at: i };
    }
  }
}

function identifierPattern(name: string): string {
  return name.replace(/\$/g, "\\$");
}

// A variable is a body only when the script visibly sends it as one, and never
// when it is spread into a request call's arguments or config.
function isBodyVariable(command: string, name: string, hops = 0): boolean {
  const n = identifierPattern(name);
  if (new RegExp(String.raw`(?:\*\*|\.\.\.)${n}\b`).test(command)) {
    return false;
  }
  const sentAsBody = new RegExp(
    String.raw`\b(?:${BODY_NAMES})\s*[=:]\s*${n}\b|\b(?:JSON\.stringify|json\.dumps|urlencode)\(\s*${n}\b`,
    "i",
  );
  if (sentAsBody.test(command)) return true;
  if (hops > 0) return false;
  const loops = new RegExp(
    String.raw`\bfor\s+([A-Za-z_]\w*)\s+in\s+${n}\b`,
    "g",
  );
  return [...command.matchAll(loops)].some((loop) =>
    isBodyVariable(command, loop[1], hops + 1),
  );
}

// Walks outward through the brackets enclosing `index` until one is opened in
// a request-body position, or a call boundary that is not one.
function isInRequestBody(command: string, index: number): boolean {
  const openers = unmatchedOpeners(command, index);
  for (const { char, at } of openers) {
    const prefix = command.slice(Math.max(0, at - 200), at);
    if (char === "(") return BODY_ENCODER_PREFIX.test(prefix);
    if (BODY_KEY_PREFIX.test(prefix)) return true;
    const forIn = FOR_IN_PREFIX.exec(prefix);
    if (forIn) return isBodyVariable(command, forIn[1]);
    const assigned = ASSIGNMENT_PREFIX.exec(prefix);
    if (assigned) {
      const outer = openers.next();
      if (!outer.done && outer.value.char === "(") {
        return new RegExp(`^(?:${BODY_NAMES})$`, "i").test(assigned[1]);
      }
      return isBodyVariable(command, assigned[1]);
    }
  }
  return false;
}

// A URL sent to the target as data (an SSRF or redirect payload) is not a host
// the command contacts. Anything not clearly in a payload position stays a
// request target, so ambiguous text still fails closed.
function isPayloadUrl(
  command: string,
  index: number,
  shellPayloads: Array<[number, number]>,
): boolean {
  if (shellPayloads.some(([start, end]) => index >= start && index < end)) {
    return true;
  }
  const prefix = command.slice(Math.max(0, index - 200), index);
  if (PARAM_VALUE_PREFIX.test(prefix)) return true;
  const objectValue = OBJECT_VALUE_PREFIX.exec(prefix);
  if (!objectValue) return false;
  const key = objectValue[1] ?? objectValue[2];
  return !REQUEST_TARGET_KEY.test(key) || isInRequestBody(command, index);
}

/**
 * Extract URLs and hostnames from a shell command string.
 *
 * Looks for:
 *  - Explicit URLs: http(s)://host..., except those in a payload position
 *  - Hostnames after common networking tools (curl, wget, nmap, etc.)
 */
export function extractHostsFromCommand(command: string): string[] {
  const hosts = new Set<string>();

  // 1. Extract the http(s) URLs the command requests
  const urlPattern = /https?:\/\/[^\s"'`;|&)<>]+/gi;
  const shellPayloads = shellPayloadRanges(command);
  for (const match of command.matchAll(urlPattern)) {
    if (isPayloadUrl(command, match.index, shellPayloads)) continue;
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

      // URLs are handled by step 1, which knows which are payloads
      if (token.match(/^https?:\/\//i)) continue;

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

  for (const hostname of commandHosts) {
    if (!isHostAllowed(hostname, allowedHosts)) {
      throw new ScopeViolationError(hostname, allowedHosts);
    }
  }
}

/**
 * Scope guard — enforces domain-level scoping for tool calls.
 *
 * When a target is configured, all outbound HTTP requests and commands
 * are checked to ensure they only hit allowed domains (hostname match).
 * Endpoint paths are intentionally NOT checked — the guard only restricts
 * the domain, not which paths the agent visits on that domain.
 *
 * Allowed domains are derived from:
 *  1. `ctx.target` (the primary target URL)
 *  2. `ctx.session.targets` (all session target URLs)
 *  3. `ctx.session.config.scopeConstraints.allowedHosts` (explicit list)
 *
 * Scope expansion: hosts derived from session targets are expanded to
 * their registrable domain (eTLD+1) via the Public Suffix List. So a
 * target of `web.dev.example.com` produces an allowed host of
 * `example.com`, which in turn permits any subdomain under it
 * (`auth.dev.example.com`, `api.example.com`, etc.). Other registrable
 * domains stay out of scope.
 *
 * Hosts in `scopeConstraints.allowedHosts` are used verbatim (not
 * expanded), so operators can narrow scope explicitly when needed.
 *
 * Subdomain matching: if `example.com` is allowed, `api.example.com` is
 * also allowed (suffix match on the hostname).
 */

import { getDomain } from "tldts";
import { parseTargetUrl } from "../../../../util/url";
import type { ResolverSession } from "../../../http/targetHeaders";
import type { ToolContext } from "./types";

/**
 * Compute the registrable domain (eTLD+1) for a hostname using the
 * Public Suffix List. Falls back to the hostname itself for IPs,
 * `localhost`, and other hosts without a recognised public suffix.
 */
export function getRegistrableDomain(hostname: string): string {
  const lower = hostname.toLowerCase();
  const domain = getDomain(lower, { allowPrivateDomains: false });
  return domain ?? lower;
}

export class ScopeViolationError extends Error {
  constructor(
    public readonly hostname: string,
    public readonly allowedHosts: string[],
  ) {
    super(
      `Scope violation: "${hostname}" is not in the list of allowed target domains [${allowedHosts.join(", ")}]. ` +
        `Only the target host and its subdomains are permitted.`,
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
  const hosts = new Set<string>();

  if (ctx.target) {
    const parsed = parseTargetUrl(ctx.target);
    if (parsed) hosts.add(getRegistrableDomain(parsed.hostname));
  }

  if (ctx.session?.targets) {
    for (const t of ctx.session.targets) {
      const parsed = parseTargetUrl(t);
      if (parsed) hosts.add(getRegistrableDomain(parsed.hostname));
    }
  }

  const explicit = ctx.session?.config?.scopeConstraints?.allowedHosts;
  if (explicit) {
    for (const h of explicit) {
      hosts.add(h.toLowerCase());
    }
  }

  return [...hosts];
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
  if (allowedHosts.length === 0) return true;

  const lower = hostname.toLowerCase();

  for (const allowed of allowedHosts) {
    const allowedLower = allowed.toLowerCase();
    if (lower === allowedLower) return true;
    if (lower.endsWith(`.${allowedLower}`)) return true;
  }

  return false;
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
  if (allowedHosts.length === 0) return;

  const hostname = extractHostname(url);
  if (!hostname) {
    throw new ScopeViolationError(url, allowedHosts);
  }

  if (!isHostAllowed(hostname, allowedHosts)) {
    throw new ScopeViolationError(hostname, allowedHosts);
  }
}

/**
 * Extract URLs and hostnames from a shell command string.
 *
 * Looks for:
 *  - Explicit URLs: http(s)://host...
 *  - Hostnames after common networking tools (curl, wget, nmap, etc.)
 */
export function extractHostsFromCommand(command: string): string[] {
  const hosts = new Set<string>();

  // 1. Extract all http(s) URLs
  const urlPattern = /https?:\/\/[^\s"'`;|&)<>]+/gi;
  for (const match of command.matchAll(urlPattern)) {
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
  if (allowedHosts.length === 0) return;

  const commandHosts = extractHostsFromCommand(command);

  for (const hostname of commandHosts) {
    if (!isHostAllowed(hostname, allowedHosts)) {
      throw new ScopeViolationError(hostname, allowedHosts);
    }
  }
}

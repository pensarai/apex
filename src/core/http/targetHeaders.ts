// Target-HTTP header resolver and the blessed primitives for outbound
// target HTTP from agent tools (`targetFetch`, `applyHeadersToShellCommand`).
// Returns empty for out-of-scope URLs to prevent credential leakage.
// Precedence: session < credential < request (later wins).
// The Biome `noRestrictedGlobals` rule forbids raw `fetch` under
// `src/core/agents/offSecAgent/tools/**` so callers must route here.

import { getDomain } from "tldts";
import { parseTargetUrl } from "../../util/url";
import type { EffectiveHeader, HeaderRecord, Layer } from "./types";

// Structural subset of session shape the resolver reads. Kept loose so
// `src/core/http/` stays a leaf module with no upward dependency on session.
export interface ResolverSession {
  readonly targets?: ReadonlyArray<string>;
  readonly config?: {
    readonly headers?: HeaderRecord;
    readonly scopeConstraints?: {
      readonly allowedHosts?: ReadonlyArray<string>;
    };
    readonly authCredentials?: unknown;
  };
  readonly credentialManager?: {
    listCredentialsWithHeaders?: () => ReadonlyArray<{
      readonly tokens?: { readonly customHeaders?: HeaderRecord };
    }>;
  };
}

// ---------------------------------------------------------------------------
// Scope check
// ---------------------------------------------------------------------------

function getRegistrableDomain(hostname: string): string {
  const lower = hostname.toLowerCase();
  return getDomain(lower, { allowPrivateDomains: false }) ?? lower;
}

function getAllowedHosts(session: ResolverSession): string[] {
  const hosts = new Set<string>();

  if (session.targets) {
    for (const t of session.targets) {
      const parsed = parseTargetUrl(t);
      if (parsed) hosts.add(getRegistrableDomain(parsed.hostname));
    }
  }

  const explicit = session.config?.scopeConstraints?.allowedHosts;
  if (explicit) {
    for (const h of explicit) {
      hosts.add(h.toLowerCase());
    }
  }

  return [...hosts];
}

function isHostInScope(hostname: string, allowedHosts: string[]): boolean {
  if (allowedHosts.length === 0) return false;
  const lower = hostname.toLowerCase();
  for (const allowed of allowedHosts) {
    if (lower === allowed) return true;
    if (lower.endsWith(`.${allowed}`)) return true;
  }
  return false;
}

function isUrlInSessionScope(url: string, session: ResolverSession): boolean {
  const parsed = parseTargetUrl(url);
  if (!parsed) return false;
  return isHostInScope(parsed.hostname, getAllowedHosts(session));
}

// ---------------------------------------------------------------------------
// Layer collection
// ---------------------------------------------------------------------------

function recordToEntries(
  record: HeaderRecord | undefined,
  source: Layer,
): EffectiveHeader[] {
  if (!record) return [];
  const out: EffectiveHeader[] = [];
  for (const [k, v] of Object.entries(record)) {
    out.push({ name: k, value: v, source });
  }
  return out;
}

function collectCredentialHeaders(session: ResolverSession): EffectiveHeader[] {
  const out: EffectiveHeader[] = [];
  const mgr = session.credentialManager;
  if (!mgr || typeof mgr.listCredentialsWithHeaders !== "function") {
    return out;
  }
  for (const cred of mgr.listCredentialsWithHeaders()) {
    const headers = cred.tokens?.customHeaders;
    if (!headers) continue;
    out.push(...recordToEntries(headers, "credential"));
  }
  return out;
}

// `requestOverrides` (e.g. the agent-supplied `headers` arg on `http_request`)
// wins over every other layer. Out-of-scope URLs only see the overrides.
export function resolveEffectiveHeaders(
  session: ResolverSession,
  url: string,
  requestOverrides?: HeaderRecord,
): HeaderRecord {
  if (!isUrlInSessionScope(url, session)) {
    return requestOverrides ?? {};
  }

  const sessionEntries = recordToEntries(session.config?.headers, "session");
  const credentialEntries = collectCredentialHeaders(session);
  const requestEntries = recordToEntries(requestOverrides, "request");

  // Later layers win on case-insensitive collision; preserve first-seen casing.
  const byCanonical = new Map<string, EffectiveHeader>();
  for (const layer of [sessionEntries, credentialEntries, requestEntries]) {
    for (const entry of layer) {
      const key = entry.name.toLowerCase();
      const prior = byCanonical.get(key);
      if (prior) {
        byCanonical.set(key, {
          name: prior.name,
          value: entry.value,
          source: entry.source,
        });
      } else {
        byCanonical.set(key, entry);
      }
    }
  }

  const out: HeaderRecord = {};
  for (const entry of byCanonical.values()) {
    out[entry.name] = entry.value;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Browser-safe header filtering
// ---------------------------------------------------------------------------

// Playwright's `extraHTTPHeaders` unconditionally overrides browser-managed
// values. Stripping User-Agent keeps Chromium's realistic UA so WAF/CDN bot
// detection isn't tripped by the session's `pensar-apex` default.
const BROWSER_MANAGED_HEADERS: ReadonlySet<string> = new Set(["user-agent"]);

export function stripBrowserManagedHeaders(
  headers: HeaderRecord | undefined,
): HeaderRecord | undefined {
  if (!headers) return headers;
  let filtered: HeaderRecord | undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (BROWSER_MANAGED_HEADERS.has(key.toLowerCase())) continue;
    filtered ??= {};
    filtered[key] = value;
  }
  return filtered;
}

// ---------------------------------------------------------------------------
// Fetch + RequestInit
// ---------------------------------------------------------------------------

function normalizeHeadersInit(
  init: HeadersInit | undefined,
): Record<string, string> {
  if (!init) return {};
  if (init instanceof Headers) {
    const out: Record<string, string> = {};
    init.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  if (Array.isArray(init)) {
    const out: Record<string, string> = {};
    for (const pair of init) {
      if (pair.length === 2) out[pair[0]!] = pair[1]!;
    }
    return out;
  }
  return { ...(init as Record<string, string>) };
}

function mergeHeadersInto(
  init: RequestInit | undefined,
  session: ResolverSession,
  url: string,
): RequestInit {
  const callerHeaders = normalizeHeadersInit(init?.headers);
  const merged = resolveEffectiveHeaders(session, url, callerHeaders);
  return {
    ...(init ?? {}),
    headers: merged,
  };
}

// Blessed fetch for target HTTP — behaves like `fetch(url, init)` plus
// resolver-merged headers. Out-of-scope URLs pass through unchanged.
export function targetFetch(
  session: ResolverSession,
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const merged = mergeHeadersInto(init, session, url);
  return fetch(url, merged);
}

// ---------------------------------------------------------------------------
// Shell injector registry
// ---------------------------------------------------------------------------

type ShellInjector = (command: string, headers: HeaderRecord) => string;

// Escape a value for use inside a double-quoted shell argument. The
// caller is responsible for wrapping the result in `"…"`.
export function shellQuote(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\$/g, "\\$")
    .replace(/`/g, "\\`")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r");
}

// Header names already on the command — skip these to avoid clobbering
// user/agent-supplied values.
function existingHeaderNames(command: string): Set<string> {
  const out = new Set<string>();
  const patterns = [
    /-H[\s=](?:"([^"]+)"|'([^']+)'|(\S+))/g,
    /--header[\s=](?:"([^"]+)"|'([^']+)'|(\S+))/g,
    /--headers[\s=](?:"([^"]+)"|'([^']+)'|(\S+))/g,
  ];
  for (const re of patterns) {
    for (const match of command.matchAll(re)) {
      const raw = match[1] ?? match[2] ?? match[3] ?? "";
      const colonIdx = raw.indexOf(":");
      if (colonIdx > 0) {
        out.add(raw.slice(0, colonIdx).trim().toLowerCase());
      }
    }
  }
  if (/(?:^|\s)(?:-A|--user-agent)[\s=]/.test(command)) {
    out.add("user-agent");
  }
  return out;
}

function buildHFlags(
  headers: HeaderRecord,
  existing: Set<string>,
  flagName: "-H" | "--header",
): string {
  const parts: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (existing.has(name.toLowerCase())) continue;
    parts.push(`${flagName} "${shellQuote(`${name}: ${value}`)}"`);
  }
  return parts.join(" ");
}

const injectCurl: ShellInjector = (command, headers) => {
  const existing = existingHeaderNames(command);
  const flags = buildHFlags(headers, existing, "-H");
  if (!flags) return command;
  return command.replace(/(?<!\/)(\bcurl\b)/, (m) => `${m} ${flags}`);
};

const injectWget: ShellInjector = (command, headers) => {
  const existing = existingHeaderNames(command);
  const parts: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (existing.has(name.toLowerCase())) continue;
    parts.push(`--header="${shellQuote(`${name}: ${value}`)}"`);
  }
  if (parts.length === 0) return command;
  const joined = parts.join(" ");
  return command.replace(/(?<!\/)(\bwget\b)/, (m) => `${m} ${joined}`);
};

const injectGenericH: (tool: string) => ShellInjector =
  (tool) => (command, headers) => {
    const existing = existingHeaderNames(command);
    const flags = buildHFlags(headers, existing, "-H");
    if (!flags) return command;
    const re = new RegExp(`(?<!/)(\\b${tool}\\b)`);
    return command.replace(re, (m) => `${m} ${flags}`);
  };

const injectSqlmap: ShellInjector = (command, headers) => {
  const existing = existingHeaderNames(command);
  const lines: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (existing.has(name.toLowerCase())) continue;
    lines.push(`${name}: ${value}`);
  }
  if (lines.length === 0) return command;
  const headerArg = `--headers="${shellQuote(lines.join("\\n"))}"`;
  return command.replace(/(?<!\/)(\bsqlmap\b)/, (m) => `${m} ${headerArg}`);
};

const injectNikto: ShellInjector = (command, headers) => {
  const existing = existingHeaderNames(command);
  const lines: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (existing.has(name.toLowerCase())) continue;
    lines.push(`${name}: ${value}`);
  }
  if (lines.length === 0) return command;
  // Literal `\n`, not 0x0A — nikto wants the two-char escape and a real
  // newline would break line-based persistent shells.
  const arg = `-headers "${shellQuote(lines.join("\\n"))}"`;
  return command.replace(/(?<!\/)(\bnikto\b)/, (m) => `${m} ${arg}`);
};

const shellInjectorRegistry: ReadonlyMap<string, ShellInjector> = new Map<
  string,
  ShellInjector
>([
  ["curl", injectCurl],
  ["wget", injectWget],
  ["nuclei", injectGenericH("nuclei")],
  ["ffuf", injectGenericH("ffuf")],
  ["gobuster", injectGenericH("gobuster")],
  ["httpx", injectGenericH("httpx")],
  ["feroxbuster", injectGenericH("feroxbuster")],
  ["dirb", injectGenericH("dirb")],
  ["wfuzz", injectGenericH("wfuzz")],
  ["wpscan", injectGenericH("wpscan")],
  ["sqlmap", injectSqlmap],
  ["nikto", injectNikto],
]);

// ---------------------------------------------------------------------------
// Shell command header injection
// ---------------------------------------------------------------------------

const COMMAND_PREFIX_STRIP =
  /^\s*(?:sudo\s+(?:-[^\s]*\s+)*|timeout\s+\S+\s+|env\s+(?:\S+=\S+\s+)+|nohup\s+)+/;

// Detect `;`, `&`, `|` outside quotes — a regex alone either matches
// operators inside quoted args or misses no-whitespace pipelines like
// `curl url|nc atk 9999`, so we walk the string with POSIX quote/escape
// rules instead.
function hasShellOperatorOutsideQuotes(command: string): boolean {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (!inSingle && ch === "\\" && i + 1 < command.length) {
      i++;
      continue;
    }
    if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }
    if (!inSingle && !inDouble) {
      if (ch === ";" || ch === "&" || ch === "|") return true;
    }
  }
  return false;
}

// Returns null for pipelined / chained commands so callers can fail closed.
function extractLeadingTool(command: string): string | null {
  if (hasShellOperatorOutsideQuotes(command)) return null;
  const stripped = command.replace(COMMAND_PREFIX_STRIP, "");
  const firstWord = stripped.trim().split(/\s+/)[0];
  return firstWord || null;
}

// Tools that operate below the HTTP layer — headers don't apply, so
// they must not be blocked by the fail-closed branch in `applyHeadersToShellCommand`.
const NON_HTTP_TOOLS: ReadonlySet<string> = new Set([
  "nmap",
  "masscan",
  "dig",
  "host",
  "whois",
  "ping",
  "traceroute",
  "ssh",
  "telnet",
  "nc",
  "ncat",
  "netcat",
  "openssl",
  "sslscan",
  "testssl",
  "hydra",
  "subfinder",
  "amass",
]);

function detectHttpToolOnCommand(command: string): string | null {
  const tool = extractLeadingTool(command);
  if (tool && shellInjectorRegistry.has(tool)) return tool;
  return null;
}

export type ApplyShellStatus = "injected" | "no-headers" | "unknown-tool";

export type ApplyShellResult = {
  readonly command: string;
  readonly status: ApplyShellStatus;
  readonly tool: string | null;
};

// Inject session/credential headers into a shell command line.
// `commandHosts` comes from scopeGuard so the two callers share one scope view.
//
// Result statuses:
//   - `no-headers`   nothing to inject (return command unchanged)
//   - `injected`     command was rewritten with -H flags
//   - `unknown-tool` headers exist but the tool/pipeline is unrecognized;
//                    the caller MUST fail closed
export function applyHeadersToShellCommand(
  command: string,
  session: ResolverSession,
  commandHosts: ReadonlyArray<string>,
): ApplyShellResult {
  const allowed = getAllowedHosts(session);
  const inScopeHost = commandHosts.find((h) => isHostInScope(h, allowed));
  if (!inScopeHost) {
    return { command, status: "no-headers", tool: null };
  }

  const url = `https://${inScopeHost}`;
  const headers = resolveEffectiveHeaders(session, url);
  if (Object.keys(headers).length === 0) {
    return { command, status: "no-headers", tool: null };
  }

  const tool = detectHttpToolOnCommand(command);
  if (!tool) {
    const leading = extractLeadingTool(command);
    if (leading && NON_HTTP_TOOLS.has(leading)) {
      return { command, status: "no-headers", tool: null };
    }
    return { command, status: "unknown-tool", tool: null };
  }

  const injector = shellInjectorRegistry.get(tool)!;
  return {
    command: injector(command, headers),
    status: "injected",
    tool,
  };
}

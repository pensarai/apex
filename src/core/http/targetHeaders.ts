/**
 * Target-HTTP headers resolver and the only blessed primitives for
 * sending target HTTP from inside agent tools.
 *
 * INV-single-source: every category-A HTTP path obtains headers via
 * `resolveEffectiveHeaders`. Tools call `targetFetch` (for fetch-based
 * paths), `mergeHeadersInto` (for cases where `RequestInit` is built
 * elsewhere), or `applyHeadersToShellCommand` (for shell tools).
 *
 * INV-blessed-fetch: tools under `src/core/agents/offSecAgent/tools/`
 * must NOT call `fetch`, `Bun.fetch`, `node:http`, or `node:https`
 * directly. The Biome rule enforces this — `targetFetch` is the only
 * way out.
 *
 * INV-scope-bound: returns empty for out-of-scope URLs to prevent
 * leakage of authentication credentials to third parties.
 *
 * INV-precedence-deterministic: layering is global → session →
 * credential → request, with later layers winning on key collision.
 */

import { getDomain } from "tldts";
import { parseTargetUrl } from "../../util/url";
import type { EffectiveHeader, HeaderRecord, Layer } from "./types";

/**
 * Structural interface for the subset of session shape this resolver
 * reads. Keeps `src/core/http/` decoupled from `src/core/session/` so
 * the resolver remains a leaf module with no upward dependency.
 */
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
  if (allowedHosts.length === 0) return true;
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

/**
 * Resolve the effective headers for an outbound request and return a
 * plain `HeaderRecord` ready to hand to `fetch` /
 * `setExtraHTTPHeaders` / curl.
 *
 * `requestOverrides` (e.g. the agent-supplied `headers` param on
 * `http_request`) wins over every other layer per
 * INV-precedence-explicit-request.
 */
export function resolveEffectiveHeaders(
  session: ResolverSession,
  url: string,
  requestOverrides?: HeaderRecord,
): HeaderRecord {
  if (!isUrlInSessionScope(url, session)) {
    return requestOverrides ?? {};
  }

  // Session layer is the only persisted set today; global defaults are
  // merged into a new session at create time (snapshot semantics).
  const sessionEntries = recordToEntries(session.config?.headers, "session");
  const credentialEntries = collectCredentialHeaders(session);
  const requestEntries = recordToEntries(requestOverrides, "request");

  // Later layers win on key collision (case-insensitive). The map keeps
  // the FIRST entry's canonical casing for display, but the LAST entry's
  // value.
  const byCanonical = new Map<string, EffectiveHeader>();
  for (const layer of [sessionEntries, credentialEntries, requestEntries]) {
    for (const entry of layer) {
      const key = entry.name.toLowerCase();
      const prior = byCanonical.get(key);
      if (prior) {
        byCanonical.set(key, {
          name: prior.name, // preserve first-seen casing
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

/**
 * Merge resolved session/global/credential headers into a `RequestInit`.
 * Any `init.headers` the caller provides is treated as the `request`
 * layer (highest precedence) per INV-precedence-explicit-request.
 *
 * No-op when the URL is out of scope or no headers are configured.
 */
function mergeHeadersInto(
  init: RequestInit | undefined,
  session: ResolverSession,
  url: string,
): RequestInit {
  const callerHeaders = normalizeHeadersInit(init?.headers);
  const merged = resolveEffectiveHeaders(session, url, callerHeaders);

  // Preserve everything else from init (method, body, signal, etc.).
  return {
    ...(init ?? {}),
    headers: merged,
  };
}

/**
 * THE blessed fetch primitive for target HTTP. Every category-A path
 * routes through this. The Biome rule forbids raw `fetch` in
 * `src/core/agents/offSecAgent/tools/**`.
 *
 * Behavior is identical to `fetch(url, init)` except that resolver
 * headers are merged in via `mergeHeadersInto`. When `url` is out of
 * scope or no headers are configured, the call behaves exactly like
 * a bare `fetch`.
 */
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

/**
 * Quote a header value for use inside a double-quoted shell argument.
 * Escapes `"`, `\`, `$`, and `` ` ``. The caller wraps the result in
 * double quotes itself.
 */
export function shellQuote(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\$/g, "\\$")
    .replace(/`/g, "\\`");
}

/**
 * Extract header names already present on the command line (so we don't
 * duplicate a header the user/agent explicitly set). Handles `-H "K:V"`
 * and `--header "K:V"` forms across most tools.
 */
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
  // curl `-A` / `--user-agent` overrides User-Agent
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
  // Insert flags after `curl` (handles `curl`, `curl ...args`).
  return command.replace(/(\bcurl\b)/, `$1 ${flags}`);
};

const injectWget: ShellInjector = (command, headers) => {
  const existing = existingHeaderNames(command);
  const parts: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (existing.has(name.toLowerCase())) continue;
    parts.push(`--header="${shellQuote(`${name}: ${value}`)}"`);
  }
  if (parts.length === 0) return command;
  return command.replace(/(\bwget\b)/, `$1 ${parts.join(" ")}`);
};

const injectGenericH: (tool: string) => ShellInjector =
  (tool) => (command, headers) => {
    const existing = existingHeaderNames(command);
    const flags = buildHFlags(headers, existing, "-H");
    if (!flags) return command;
    const re = new RegExp(`(\\b${tool}\\b)`);
    return command.replace(re, `$1 ${flags}`);
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
  return command.replace(/(\bsqlmap\b)/, `$1 ${headerArg}`);
};

const injectNikto: ShellInjector = (command, headers) => {
  const existing = existingHeaderNames(command);
  const lines: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (existing.has(name.toLowerCase())) continue;
    lines.push(`${name}: ${value}`);
  }
  if (lines.length === 0) return command;
  const arg = `-headers "${shellQuote(lines.join("\n"))}"`;
  return command.replace(/(\bnikto\b)/, `$1 ${arg}`);
};

/**
 * Registry of recognized HTTP CLI tools and how to inject headers into
 * each. Data, not code: adding a new tool is one entry, not a new
 * branch in a switch.
 */
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

const COMMAND_SPLIT = /(?:^|\s)(?:[;&|]{1,2})/;
const COMMAND_PREFIX_STRIP =
  /^\s*(?:sudo\s+(?:-[^\s]*\s+)*|timeout\s+\S+\s+|env\s+(?:\S+=\S+\s+)+|nohup\s+)+/;

/**
 * Identify the first HTTP tool name on a command line, stripping common
 * wrappers (`sudo`, `timeout N`, `env K=V`, `nohup`). Returns `null` if
 * the leading word is not in `shellInjectorRegistry` or if the command
 * is pipelined / chained (the safe answer in that case is "don't
 * inject" so the caller can fail closed).
 */
function detectHttpToolOnCommand(command: string): string | null {
  // Reject pipelined / chained commands — we cannot safely inject into
  // a pipeline. Caller fails closed.
  if (COMMAND_SPLIT.test(` ${command}`)) return null;

  const stripped = command.replace(COMMAND_PREFIX_STRIP, "");
  const firstWord = stripped.trim().split(/\s+/)[0];
  if (!firstWord) return null;

  if (shellInjectorRegistry.has(firstWord)) return firstWord;
  return null;
}

export type ApplyShellStatus = "injected" | "no-headers" | "unknown-tool";

export type ApplyShellResult = {
  readonly command: string;
  readonly status: ApplyShellStatus;
  readonly tool: string | null;
};

/**
 * Inject session/global/credential headers into a shell command line.
 *
 * Behavior matrix:
 *  - no in-scope hosts on the command → `no-headers` (return as-is)
 *  - in-scope but no headers configured → `no-headers` (return as-is)
 *  - in-scope + headers + known tool → `injected` (return augmented)
 *  - in-scope + headers + unknown tool / pipelined → `unknown-tool`
 *    (caller MUST fail closed; INV-shell-injection)
 *
 * `commandHosts` is the list of hosts on the command line (extracted by
 * the caller via scopeGuard). This module deliberately does not parse
 * the command for hosts — that logic already lives in scopeGuard and
 * duplicating it would diverge.
 */
export function applyHeadersToShellCommand(
  command: string,
  session: ResolverSession,
  commandHosts: ReadonlyArray<string>,
): ApplyShellResult {
  // Find the highest-scope URL-like target on the command line and use
  // it to drive the resolver. If no host is present, there's nothing
  // to inject for.
  const inScopeHost = commandHosts.find((h) => {
    const allowed = getAllowedHosts(session);
    return isHostInScope(h, allowed);
  });
  if (!inScopeHost) {
    return { command, status: "no-headers", tool: null };
  }

  // Build a synthetic URL so the resolver's scope check sees the host.
  const url = `https://${inScopeHost}`;
  const headers = resolveEffectiveHeaders(session, url);
  if (Object.keys(headers).length === 0) {
    return { command, status: "no-headers", tool: null };
  }

  const tool = detectHttpToolOnCommand(command);
  if (!tool) {
    return { command, status: "unknown-tool", tool: null };
  }

  const injector = shellInjectorRegistry.get(tool)!;
  return {
    command: injector(command, headers),
    status: "injected",
    tool,
  };
}

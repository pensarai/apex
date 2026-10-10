// Target-HTTP header resolver and the blessed primitives for outbound
// target HTTP from agent tools (`targetFetch`, `applyHeadersToShellCommand`).
// Returns empty for out-of-scope URLs to prevent credential leakage.
// Precedence: session < credential < request (later wins).
// The Biome `noRestrictedGlobals` rule forbids raw `fetch` under
// `src/core/agents/offSecAgent/tools/**` so callers must route here.

import {
  getSessionAllowedHosts,
  isHostInScope,
  isUrlInSessionScope,
} from "./targetScope";
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
  // newline would break line-based shell argument parsing.
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

// A character that may sit on either side of a literal `2>&1` token
// without extending it into a larger shell word. Quote characters and `(`
// are NOT boundaries: after the target, `2>&1"x"` / `2>&1(…)` concatenate
// onto the expandable target word; before the `2`, a word character means
// the digits are an fd number (`32>&1`) or a word suffix (`api2>&1`), not
// the literal merge.
function isStderrMergeBoundary(ch: string | undefined): boolean {
  if (ch === undefined) return true;
  return /[\s;&|<>)]/.test(ch);
}

// `$` starts a live expansion — parameter (`$VAR`, `${…}`, `$1`, `$$`),
// command (`$(…)`), or arithmetic (`$((…))`) — unless the next character
// cannot continue one, in which case it is a literal dollar.
function isDollarExpansionStart(ch: string | undefined): boolean {
  if (ch === undefined) return false;
  return /[A-Za-z_0-9({@$!*?#$-]/.test(ch);
}

// True when the `&` at index i is the ampersand of an unquoted, unescaped
// literal `2>&1` (stderr duplicated onto stdout) standing as its own
// token. POSIX shells expand the target of `N>&word`, so `2>&$fd` or
// `2>&1$(…)` can execute substitutions, and glued digits are a different
// fd or a bare dup — only this exact token, bounded on both sides, is
// treated as a redirect; every other `&` keeps the chaining
// classification.
function isStderrMergeAt(command: string, i: number): boolean {
  return (
    isStderrMergeBoundary(command[i - 3]) &&
    command[i - 2] === "2" &&
    command[i - 1] === ">" &&
    command[i + 1] === "1" &&
    isStderrMergeBoundary(command[i + 2])
  );
}

type OperatorScan = {
  // `;`, `&`, `|` outside quotes — including a `2>&1` `&` whose redirect
  // recognition was vetoed below
  hasOperator: boolean;
  // the command contains a literal `2>&1` recognized as a redirect
  stderrMerge: boolean;
};

// Detect `;`, `&`, `|` outside quotes — a regex alone either matches
// operators inside quoted args or misses no-whitespace pipelines like
// `curl url|nc atk 9999`, so we walk the string with POSIX quote/escape
// rules instead.
// Quote characters must sit at word boundaries on the descriptor path:
// a quote glued to a word character concatenates fragments into one argv
// word the literal text never shows (`https://"attacker.net"/x` arrives
// as a single URL).
function isQuoteGluedToWord(
  command: string,
  i: number,
  opening: boolean,
): boolean {
  const neighbor = opening ? command[i - 1] : command[i + 1];
  if (neighbor === undefined) return false;
  return !/[\s;&|<>()]/.test(neighbor);
}

function scanShellOperators(
  command: string,
  allowDescriptorRedirect: boolean,
): OperatorScan {
  let inSingle = false;
  let inDouble = false;
  let mergeCandidate = false;
  // Live substitution, runtime word expansion, or an unquoted newline (a
  // command separator) anywhere in the command reverts the merge `&` to
  // its chaining classification — the descriptor path admits only what
  // its lexical scan can fully establish as argv.
  let activeExpansion = false;
  let unquotedNewline = false;
  let wordStarted = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (
      allowDescriptorRedirect &&
      !inSingle &&
      !inDouble &&
      ch === "#" &&
      !wordStarted
    ) {
      // Quotes in a POSIX comment cannot hide its terminating newline.
      const newline = command.indexOf("\n", i);
      if (newline === -1) break;
      i = newline - 1;
      continue;
    }
    if (!inSingle && !inDouble) {
      wordStarted = ch !== " " && ch !== "\t" && ch !== "\n";
    }
    if (!inSingle && ch === "\\" && i + 1 < command.length) {
      // Any backslash outside single quotes can rewrite an argv word:
      // escape removal (`attac\ker.net` → `attacker.net`), quote
      // escaping, or a line continuation joining fragments
      // (`https:` + `\` + newline + `//other.test` assembles a URL raw
      // extraction never sees — inside double quotes too).
      activeExpansion = true;
      i++;
      continue;
    }
    // curl itself globs `{a,b}` / `[0-1]` URL operands — quoting makes an
    // argument shell-inert, not destination-inert (a quoted `file://{a,b}`
    // yields two requests) — and telling a URL operand from a
    // brace-bearing payload takes curl-grammar parsing. The descriptor
    // path stays narrower: no brace or bracket text in any quote state.
    if (ch === "{" || ch === "}" || ch === "[" || ch === "]") {
      activeExpansion = true;
      continue;
    }
    if (!inDouble && ch === "'") {
      if (isQuoteGluedToWord(command, i, !inSingle)) activeExpansion = true;
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && ch === '"') {
      if (isQuoteGluedToWord(command, i, !inDouble)) activeExpansion = true;
      inDouble = !inDouble;
      continue;
    }
    if (inSingle) continue;
    // Backticks and `$`-expansions stay live inside double quotes; single
    // quotes make them literal text. A `$SECOND_URL` arg could name a host
    // no scope check has verified, and unquoted `$'…'` / `$"…"` (ANSI-C /
    // translated quoting) decode at runtime, so any live extension vetoes
    // the `2>&1` redirect recognition below. `$` before a closing quote
    // inside `"…"` stays a literal dollar.
    if (
      ch === "`" ||
      (ch === "$" &&
        (isDollarExpansionStart(command[i + 1]) ||
          (!inDouble && (command[i + 1] === "'" || command[i + 1] === '"'))))
    ) {
      activeExpansion = true;
      continue;
    }
    if (inDouble) continue;
    if (ch === "\n") {
      unquotedNewline = true;
      continue;
    }
    // Unquoted `*`/`?` are shell pathname globs: patterns can match local
    // directory trees (including a planted `https:/…` tree), so a slash
    // in the word does not make them safe. Quoted forms stay supported —
    // the shell passes them verbatim and curl does not glob on them.
    if (ch === "*" || ch === "?") {
      activeExpansion = true;
      continue;
    }
    // Extglob paren forms (`+(…)`, `@(…)`, `!(…)`; `?(…)` and `*(…)` are
    // covered above) — rejected conservatively rather than assuming the
    // executor leaves extglob off. Word-initial unquoted `~` tilde-expands
    // into a home path; mid-word (`https://example.com/~user`) it is literal.
    if (
      ((ch === "+" || ch === "@" || ch === "!") && command[i + 1] === "(") ||
      (ch === "~" && (i === 0 || /\s/.test(command[i - 1] ?? "")))
    ) {
      activeExpansion = true;
      continue;
    }
    // Process substitution is live only unquoted.
    if ((ch === "<" || ch === ">") && command[i + 1] === "(") {
      activeExpansion = true;
      continue;
    }
    // `2>&1` recognition is proven for POSIX shells only — the same bytes
    // in Windows cmd keep the legacy chaining classification.
    if (allowDescriptorRedirect && ch === "&" && isStderrMergeAt(command, i)) {
      mergeCandidate = true;
      i++; // skip the merge target digit
      continue;
    }
    if (ch === ";" || ch === "&" || ch === "|") {
      return { hasOperator: true, stderrMerge: false };
    }
  }
  const stderrMerge = mergeCandidate && !activeExpansion && !unquotedNewline;
  return { hasOperator: mergeCandidate && !stderrMerge, stderrMerge };
}

// Returns null for pipelined / chained commands so callers can fail closed.
function extractLeadingTool(
  command: string,
  allowDescriptorRedirect: boolean,
): string | null {
  if (scanShellOperators(command, allowDescriptorRedirect).hasOperator)
    return null;
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

function detectHttpToolOnCommand(
  command: string,
  allowDescriptorRedirect: boolean,
): string | null {
  const tool = extractLeadingTool(command, allowDescriptorRedirect);
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
// `platform` is the selected command backend's platform; the literal `2>&1`
// descriptor recognition applies only to POSIX-contract shells.
//
// Result statuses:
//   - `no-headers`   nothing to inject (return command unchanged)
//   - `injected`     command was rewritten with -H flags
//   - `unknown-tool` headers exist but the tool/pipeline is unrecognized,
//                    or a `2>&1`-redirected command spans multiple hosts;
//                    the caller MUST fail closed
export function applyHeadersToShellCommand(
  command: string,
  session: ResolverSession,
  commandHosts: ReadonlyArray<string>,
  platform?: "posix" | "windows",
): ApplyShellResult {
  // The `2>&1` redirect recognition is proven for POSIX shells only; a
  // Windows cmd/powershell backend keeps the legacy fail-closed
  // classification for those bytes. An absent platform follows the
  // CommandBackend contract — custom transports default to POSIX
  // regardless of host OS.
  const allowDescriptorRedirect = platform !== "windows";
  const allowed = getSessionAllowedHosts(session);
  const inScopeHost = commandHosts.find((h) => isHostInScope(h, allowed));
  if (!inScopeHost) {
    return { command, status: "no-headers", tool: null };
  }

  const url = `https://${inScopeHost}`;
  const headers = resolveEffectiveHeaders(session, url);
  if (Object.keys(headers).length === 0) {
    return { command, status: "no-headers", tool: null };
  }

  const tool = detectHttpToolOnCommand(command, allowDescriptorRedirect);
  if (!tool) {
    const leading = extractLeadingTool(command, allowDescriptorRedirect);
    if (leading && NON_HTTP_TOOLS.has(leading)) {
      return { command, status: "no-headers", tool: null };
    }
    return { command, status: "unknown-tool", tool: null };
  }

  // Injected flags ride every URL on the line — `curl urlA urlB` sends each
  // -H to both hosts — so the newly recognized `2>&1` must not widen
  // acceptance for multi-host commands the operator check used to block.
  // (Scope enforcement for all commands stays in the caller's scope guard.)
  if (
    new Set(commandHosts).size > 1 &&
    scanShellOperators(command, allowDescriptorRedirect).stderrMerge
  ) {
    return { command, status: "unknown-tool", tool: null };
  }

  const injector = shellInjectorRegistry.get(tool)!;
  return {
    command: injector(command, headers),
    status: "injected",
    tool,
  };
}

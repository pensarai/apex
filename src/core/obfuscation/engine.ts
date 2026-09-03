/**
 * Pattern-based obfuscation engine.
 *
 * The engine maintains a process-lifetime map of `original → placeholder`
 * so the same value produces the same placeholder every time. Placeholders
 * use square brackets (`[EMAIL_1]`) — angle brackets would be parsed as
 * inline HTML by the markdown renderer and disappear from the rendered
 * message, so brackets keep the placeholder visible across every render
 * path.
 *
 * Hosts have **no allowlist**: every detected hostname is redacted, even
 * apparently public ones (e.g. `pensar.dev`, `github.com`). The point of
 * obfuscate-mode is screenshot safety, and any host in the transcript is
 * potential signal — including the operator's own infrastructure.
 */

export type ObfuscationCategory =
  | "EMAIL"
  | "UUID"
  | "URL"
  | "HOST"
  | "IPV4"
  | "IPV6"
  | "MAC"
  | "PATH"
  | "JWT"
  | "TOKEN"
  | "HEX"
  | "PHONE"
  | "CARD"
  | "ORG"
  | "USER";

interface Mapping {
  category: ObfuscationCategory;
  index: number;
}

const STATE = {
  enabled: false,
  counters: new Map<ObfuscationCategory, number>(),
  mapping: new Map<string, Mapping>(),
  /**
   * Lowercase `label → Mapping` aliases derived from previously-redacted
   * values: when we redact `acme.com → [HOST_42]` we also register
   * `acme → [HOST_42]` so bare references to the same org get the
   * same placeholder. Same idea for `Acme Corp → [ORG_3]` registering
   * `acme → [ORG_3]`.
   *
   * Aliases share placeholders with their parent value, so deobfuscation
   * resolves `[HOST_42]` to the canonical hostname regardless of which
   * surface (full host vs. bare label) produced the placeholder.
   */
  aliases: new Map<string, Mapping>(),
};

/**
 * Generic SaaS / cloud / infra labels that should never be aliased even
 * when they appear inside a redacted hostname. Without this filter,
 * `s3.amazonaws.com` would teach the engine that `amazonaws` is a
 * sensitive label and start redacting every mention of "Amazon" or
 * "AWS" in agent prose.
 */
const PROVIDER_LABELS = new Set<string>([
  "amazon",
  "amazonaws",
  "amazonses",
  "amazonsns",
  "amazoncognito",
  "google",
  "googleapis",
  "googleusercontent",
  "gstatic",
  "github",
  "githubusercontent",
  "gitlab",
  "bitbucket",
  "cloudflare",
  "cloudflareinsights",
  "cloudfront",
  "azure",
  "azurewebsites",
  "microsoft",
  "microsoftonline",
  "office",
  "windows",
  "outlook",
  "slack",
  "atlassian",
  "jira",
  "heroku",
  "vercel",
  "netlify",
  "digitalocean",
  "linode",
  "fastly",
  "akamai",
  "edgekey",
  "edgesuite",
  "stripe",
  "paypal",
  "shopify",
  "wordpress",
  "blogspot",
  "twitter",
  "facebook",
  "instagram",
  "linkedin",
  "youtube",
  "discord",
  "twitch",
  "zoom",
  "dropbox",
  "okta",
  "auth0",
  "duo",
  "cognito",
  "salesforce",
  "hubspot",
  "intercom",
  "zendesk",
  "sendgrid",
  "twilio",
  "mailgun",
  "datadog",
  "sentry",
  "newrelic",
  "rollbar",
  "segment",
  "mixpanel",
  "amplitude",
  "stackoverflow",
  "medium",
  "reddit",
  "wikipedia",
  "localhost",
  "example",
]);

/** Words used as `org` placeholder bait — these are not redacted. */
const ORG_STOPWORDS = new Set<string>([
  "Pensar",
  "Apex",
  "Linux",
  "Windows",
  "MacOS",
  "Ubuntu",
  "Debian",
  "Fedora",
  "Bun",
  "Node",
  "TypeScript",
  "JavaScript",
  "Python",
  "Java",
  "Go",
  "Rust",
  "Docker",
  "Kubernetes",
  "GitHub",
  "Anthropic",
  "OpenAI",
  "Google",
  "AWS",
  "Azure",
  "Claude",
  "GPT",
  "Sonnet",
  "Opus",
  "Haiku",
  "User",
  "Admin",
  "Test",
  "Dev",
  "Prod",
  "Staging",
  "TODO",
  "README",
  "API",
  "URL",
  "HTTP",
  "HTTPS",
  "JSON",
  "XML",
  "YAML",
  "CSV",
  "PDF",
  "HTML",
  "CSS",
  "SQL",
  "TLS",
  "SSL",
  "JWT",
  "UUID",
  "CWE",
  "CVE",
  "OS",
  "PII",
  "URI",
  "IDE",
  "CLI",
  "TUI",
  "SDK",
  "MCP",
  "REST",
  "GraphQL",
  "OAuth",
  "SSO",
  "IAM",
  "VPN",
  "DNS",
  "ICMP",
  "TCP",
  "UDP",
]);

/**
 * Patterns are run in this order. Order matters because once a substring
 * is replaced with `[CATEGORY_N]`, it can no longer match later patterns.
 *
 * Each pattern receives the full match and returns the substring that
 * should be tracked / replaced. The optional `pick` filter exists so a
 * pattern can opt out of redacting specific matches (e.g. anything that
 * looks like a source-code filename).
 */
interface Pattern {
  category: ObfuscationCategory;
  /** Regex with the global flag set. */
  regex: RegExp;
  /**
   * Optional filter: return null to keep the original substring,
   * otherwise return the substring to track + replace.
   */
  pick?: (match: RegExpExecArray) => string | null;
}

const URL_REGEX =
  /\bhttps?:\/\/(?:[A-Za-z0-9._~%!$&'()*+,;=:@-]+\/?)+(?:\?[^\s<>"]*)?(?:#[^\s<>"]*)?/g;

const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g;

const UUID_REGEX =
  /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

const IPV4_REGEX =
  /\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}\b/g;

/**
 * IPv4 written with hyphens instead of dots (e.g. `10-0-0-1`). Common in
 * filesystem-safe session names and reverse-DNS labels like
 * `pentest-10-0-0-1` or `ec2-54-12-34-56.compute.amazonaws.com`.
 *
 * Lookbehind/lookahead reject continuation of a longer hyphenated number
 * sequence (so `1-2-3-4-5` does not match `2-3-4-5` once `1-2-3-4` is
 * rejected by the trailing lookahead).
 */
const IPV4_DASHED_REGEX =
  /(?<![0-9])(?<!\d-)(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:-(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}(?![0-9])(?!-\d)/g;

// Match both full and compressed (`fe80::1`, `2001:db8::8a2e`) IPv6 forms.
// Compressed: contains `::`. Full: has 7 colons separating 8 hex groups.
const IPV6_REGEX =
  /\b(?:(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{0,4}|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4})|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)\b/g;

const MAC_REGEX = /\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/g;

const JWT_REGEX =
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

const TOKEN_REGEX =
  /\b(?:sk-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{20,}|pk_(?:live|test)_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b/g;

const HEX_REGEX = /\b[0-9a-fA-F]{32,128}\b/g;

const CARD_REGEX = /\b(?:\d[ -]?){13,19}\b/g;

const PHONE_REGEX = /\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/g;

const PATH_UNIX_REGEX =
  /\/(?:Users|home)\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._\- /+]*)?/g;
const PATH_WIN_REGEX =
  /[A-Za-z]:\\Users\\[A-Za-z0-9._-]+(?:\\[A-Za-z0-9._\- \\+]*)?/g;

/**
 * URL-style filesystem and HTTP route paths with a leading slash, e.g.
 * `/v1/external/sendgrid/{tenant_id}`, `/__debug/pprof/heap`,
 * `/tmp/cache.json`, `/docs/`, `/__health`, `/login,`.
 *
 * Four alternatives, ordered greediest-first so multi-segment matches
 * absorb `__`-prefixed first segments:
 *   1. multi-segment path: `/foo/bar`, `/v1/users/{id}`
 *   2. `__`-prefixed single segment: `/__debug`, `/__health`
 *   3. single segment with trailing slash: `/docs/`
 *   4. single segment followed by some character or whitespace
 *      (anything but newline/EOS): `/login,`, `/dashboard `, `/leads.`
 *
 * Alternative 4 deliberately requires SOMETHING after the segment so
 * a bare standalone slash command (`/help`, `/obfuscate` at end of
 * input or end of line) stays intact for the command router. The
 * PromptInput layer additionally skips real-time obfuscation when the
 * buffer begins with `/`, so user-typed commands with arguments
 * (`/threat-model --output foo/bar`) aren't mangled either; the
 * remaining false positives are agent prose like "run /obfuscate now",
 * which we accept.
 *
 * Inner segment chars accept `{}`, `[]`, and `$` so existing
 * placeholder values (`{tenant_id}`, `${userId}`, `[UUID_3]`) and
 * earlier obfuscation results get folded into the surrounding path.
 */
const ROUTE_PATH_REGEX =
  /(?<![A-Za-z0-9_./-])\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.{}$[\]-]*)+\/?|__[A-Za-z0-9_.-]+\/?|[A-Za-z0-9_.-]+\/|[A-Za-z0-9_.-]+(?=[^A-Za-z0-9_.\-\n\r]))/g;

/**
 * Multi-segment path WITHOUT a leading slash: `__debug/config`,
 * `docs/media/`, `v2/access/users/type`, `media/{tenant_id}`,
 * `access/users/${userId}/tenants`.
 *
 * Aggressive on purpose — operators would rather over-redact paths
 * than leak endpoint surface. Side effect: trivially matches phrases
 * like `and/or`, `key/value`, dates such as `04/28/2026`, and
 * `12/30/2025`. We accept those false positives.
 */
const RELATIVE_PATH_REGEX =
  /(?<![A-Za-z0-9_./\\-])[A-Za-z0-9_.-]+\/(?:[A-Za-z0-9_.{}$[\]-]*\/)*[A-Za-z0-9_.{}$[\]-]*/g;

/**
 * Region-prefixed AWS identifiers such as Cognito user-pool IDs
 * (`us-east-1_X8rlYugE7`) and similar `<region>_<base62>` blobs.
 * Region alone (`us-east-1`) is left intact — only the suffixed form
 * is sensitive.
 */
const AWS_REGION_ID_REGEX =
  /\b(?:us|eu|ap|sa|ca|me|af|cn)-(?:north|south|east|west|central|southeast|northeast|southwest|northwest)-\d_[A-Za-z0-9]{6,}\b/g;

/**
 * Opaque alphanumeric blob 20+ chars containing both letters and at
 * least one digit. Catches AWS/GCP client IDs, Cognito identity blobs,
 * session tokens, and other long mixed-case identifiers that don't
 * match a vendor-specific prefix. The double lookahead requires both
 * a digit and a letter so we don't redact long all-letter strings
 * (concatenated identifiers like `getUserTenants`) or all-digit
 * strings (handled by phone/card patterns).
 */
const OPAQUE_ID_REGEX =
  /\b(?=[A-Za-z0-9]{20,}\b)(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{20,}\b/g;

/**
 * Bare hostnames such as `acme-corp.internal`, `target.example.com`,
 * `s3-bucket.eu-west-1.amazonaws.com`. Caught after URLs so the URL
 * pass takes precedence.
 */
const HOST_REGEX =
  /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g;

/**
 * Capitalised compound nouns that look like company / product names,
 * e.g. `Acme Corp`, `Globex Industries`, `Initech LLC`.
 *
 * Uses a sliding window of capitalised tokens. Single capitalised words
 * are too noisy (every sentence start would match), so we require either
 * a corporate suffix (`Inc`, `LLC`, ...) or two consecutive capitalised
 * words.
 */
const ORG_SUFFIXES =
  "(?:Inc|LLC|Ltd|Limited|Corp|Corporation|Co|Holdings|Group|GmbH|S\\.?A\\.?|Industries|Solutions|Systems|Technologies|Labs|Networks|Bank|Capital|Partners|Pty)";

const ORG_REGEX = new RegExp(
  `\\b(?:[A-Z][a-zA-Z0-9&'-]+(?:\\s+[A-Z][a-zA-Z0-9&'-]+){0,3})\\s+${ORG_SUFFIXES}\\.?\\b`,
  "g",
);

const PATTERNS: Pattern[] = [
  { category: "URL", regex: URL_REGEX },
  { category: "EMAIL", regex: EMAIL_REGEX },
  { category: "JWT", regex: JWT_REGEX },
  { category: "TOKEN", regex: TOKEN_REGEX },
  { category: "UUID", regex: UUID_REGEX },
  { category: "MAC", regex: MAC_REGEX },
  { category: "IPV6", regex: IPV6_REGEX },
  { category: "IPV4", regex: IPV4_REGEX },
  { category: "IPV4", regex: IPV4_DASHED_REGEX },
  {
    category: "CARD",
    regex: CARD_REGEX,
    pick: (m) => {
      const digits = m[0].replace(/[ -]/g, "");
      if (digits.length < 13 || digits.length > 19) return null;
      return luhn(digits) ? m[0] : null;
    },
  },
  {
    category: "PHONE",
    regex: PHONE_REGEX,
    pick: (m) => {
      const digits = m[0].replace(/\D/g, "");
      if (digits.length < 10 || digits.length > 15) return null;
      return m[0];
    },
  },
  { category: "TOKEN", regex: AWS_REGION_ID_REGEX },
  { category: "PATH", regex: PATH_UNIX_REGEX },
  { category: "PATH", regex: PATH_WIN_REGEX },
  { category: "PATH", regex: ROUTE_PATH_REGEX },
  { category: "PATH", regex: RELATIVE_PATH_REGEX },
  { category: "TOKEN", regex: OPAQUE_ID_REGEX },
  {
    category: "HOST",
    regex: HOST_REGEX,
    pick: (m) => {
      const host = m[0].toLowerCase();
      // Skip anything that looks like a filename (`config.json`, `app.py`)
      // so source-code references don't get redacted as fake hostnames.
      if (
        /^[a-z]+\.(?:json|js|ts|tsx|jsx|md|txt|csv|xml|yaml|yml|toml|sh|py|rb|go|rs|java|css|html|log|lock|env)$/.test(
          host,
        )
      ) {
        return null;
      }
      return m[0];
    },
  },
  { category: "HEX", regex: HEX_REGEX },
  {
    category: "ORG",
    regex: ORG_REGEX,
    pick: (m) => {
      const text = m[0].trim();
      if (ORG_STOPWORDS.has(text.split(/\s+/)[0]!)) return null;
      return text;
    },
  },
];

function luhn(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function placeholderFor(value: string, category: ObfuscationCategory): string {
  const existing = STATE.mapping.get(value);
  if (existing) {
    learnAliases(value, category, existing);
    return `[${existing.category}_${existing.index}]`;
  }
  const next = (STATE.counters.get(category) ?? 0) + 1;
  STATE.counters.set(category, next);
  const mapping: Mapping = { category, index: next };
  STATE.mapping.set(value, mapping);
  learnAliases(value, category, mapping);
  return `[${category}_${next}]`;
}

/**
 * Pull a "registrable" label out of a hostname, e.g. `acme` from
 * `acme.com` or `staging-console.acme.dev`. Returns null when the
 * label is too short, looks like a TLD, has no letters, or is in the
 * global provider blocklist.
 */
function extractHostLabel(host: string): string | null {
  const cleaned = host.toLowerCase().replace(/^\[|\]$/g, "");
  const parts = cleaned.split(".").filter(Boolean);
  if (parts.length < 2) return null;
  const label = parts[parts.length - 2];
  if (!label) return null;
  if (label.length < 4) return null;
  if (!/[a-z]/.test(label)) return null;
  if (PROVIDER_LABELS.has(label)) return null;
  return label;
}

/** Pull the host out of an `https://host[:port]/path...` URL match. */
function extractHostFromUrl(url: string): string | null {
  const m = /^https?:\/\/([^\/?#:]+)/i.exec(url);
  return m?.[1] ? m[1] : null;
}

/**
 * Pull the leading capitalised word out of an org match, e.g. `Acme`
 * from `Acme Corp` or `Globex Industries`. Skips the corporate suffix
 * itself (`Corp`, `LLC`, ...) and any token already in the stopword
 * list so well-known platforms don't get aliased.
 */
function extractOrgLabel(text: string): string | null {
  const first = text.trim().split(/\s+/)[0];
  if (!first) return null;
  if (first.length < 4) return null;
  if (ORG_STOPWORDS.has(first)) return null;
  const lower = first.toLowerCase();
  if (PROVIDER_LABELS.has(lower)) return null;
  return lower;
}

function recordAlias(label: string | null, mapping: Mapping): void {
  if (!label) return;
  if (STATE.aliases.has(label)) return;
  STATE.aliases.set(label, mapping);
}

function learnAliases(
  value: string,
  category: ObfuscationCategory,
  mapping: Mapping,
): void {
  switch (category) {
    case "HOST":
      recordAlias(extractHostLabel(value), mapping);
      break;
    case "URL": {
      const host = extractHostFromUrl(value);
      if (host) recordAlias(extractHostLabel(host), mapping);
      break;
    }
    case "ORG":
      recordAlias(extractOrgLabel(value), mapping);
      break;
    default:
      break;
  }
}

/** Escape regex metacharacters in a literal string. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Replace every learned alias with its placeholder, case-insensitive,
 * whole-word. Run as a final pass after the regex patterns so the
 * aliases mostly act on agent prose ("the Acme corporate tenant")
 * rather than the structured values the patterns already handled.
 */
function applyAliases(input: string): string {
  if (STATE.aliases.size === 0) return input;
  const labels = Array.from(STATE.aliases.keys()).sort(
    (a, b) => b.length - a.length,
  );
  const regex = new RegExp(
    `\\b(?:${labels.map(escapeRegex).join("|")})\\b`,
    "gi",
  );
  return input.replace(regex, (match) => {
    const mapping = STATE.aliases.get(match.toLowerCase());
    if (!mapping) return match;
    return `[${mapping.category}_${mapping.index}]`;
  });
}

/** Globally enable/disable obfuscation. */
export function setObfuscationEnabled(enabled: boolean): void {
  STATE.enabled = enabled;
}

/** Whether obfuscation is currently active. */
export function isObfuscationEnabled(): boolean {
  return STATE.enabled;
}

/** Reset the placeholder mapping. Mostly useful in tests. */
export function resetObfuscation(): void {
  STATE.counters.clear();
  STATE.mapping.clear();
  STATE.aliases.clear();
}

/**
 * Redact a string. When obfuscation is disabled, the input is returned
 * unchanged. When enabled, every recognised pattern is replaced with a
 * stable placeholder.
 *
 * `options.aliases` (default `true`) controls the final org-label
 * replacement pass. The PromptInput layer disables it because aliases
 * are lossy to round-trip: typing the bare label `Acme` would
 * obfuscate to `[HOST_42]` and deobfuscate back to the canonical host
 * (`acme.com`), corrupting the user's input. Display surfaces
 * (renderer, tool output) keep aliasing on since they never round-trip.
 */
export function obfuscate(
  input: string,
  options?: { aliases?: boolean },
): string {
  if (!STATE.enabled) return input;
  if (!input) return input;

  let output = input;
  for (const pattern of PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    output = output.replace(regex, (match, ..._rest) => {
      const arr = [match] as unknown as RegExpExecArray;
      arr.index = 0;
      arr.input = output;
      const tracked = pattern.pick ? pattern.pick(arr) : match;
      if (tracked === null) return match;
      return placeholderFor(tracked, pattern.category);
    });
  }
  // Final pass: case-insensitive whole-word replacement of any org
  // labels we learned from previously-redacted hosts/URLs/orgs. This
  // is what catches bare references like "the Acme subdomain"
  // once the engine has seen `acme.com` or `Acme Inc.`.
  if (options?.aliases !== false) {
    output = applyAliases(output);
  }
  return output;
}

/**
 * Reverse `obfuscate()`/`obfuscateValue()` — replace every known
 * `[CATEGORY_N]` placeholder with the original value it was generated
 * from. Unknown placeholders are left intact.
 *
 * Used by inputs that redact text in-place while the user types: the
 * textarea displays placeholders, but the agent must receive the
 * original values on submit.
 *
 * Reversal is unconditional — it works even when obfuscation is
 * disabled, so a value that was redacted before obfuscation was toggled
 * off still resolves cleanly.
 */
export function deobfuscate(input: string): string {
  if (!input || STATE.mapping.size === 0) return input;
  // Sort by descending index per category so longer placeholders
  // (`[HOST_10]`) are tried before their prefixes (`[HOST_1]`). Both are
  // unique strings, but ordering keeps the regex shape simple if we
  // ever switch to a single combined pass.
  const entries = Array.from(STATE.mapping.entries()).sort(
    ([, a], [, b]) => b.index - a.index,
  );
  let output = input;
  for (const [original, { category, index }] of entries) {
    const placeholder = `[${category}_${index}]`;
    if (!output.includes(placeholder)) continue;
    output = output.split(placeholder).join(original);
  }
  return output;
}

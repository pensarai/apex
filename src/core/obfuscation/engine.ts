/**
 * Pattern-based obfuscation engine.
 *
 * The engine maintains a process-lifetime map of `original → placeholder`
 * so the same value produces the same placeholder every time. Placeholders
 * use angle brackets (`<EMAIL_1>`) so they are obviously not real data and
 * cannot collide with any of the regexes below.
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
};

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
 * is replaced with `<CATEGORY_N>`, it can no longer match later patterns.
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
  { category: "PATH", regex: PATH_UNIX_REGEX },
  { category: "PATH", regex: PATH_WIN_REGEX },
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
    return `<${existing.category}_${existing.index}>`;
  }
  const next = (STATE.counters.get(category) ?? 0) + 1;
  STATE.counters.set(category, next);
  STATE.mapping.set(value, { category, index: next });
  return `<${category}_${next}>`;
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
}

/**
 * Redact a string. When obfuscation is disabled, the input is returned
 * unchanged. When enabled, every recognised pattern is replaced with a
 * stable placeholder.
 */
export function obfuscate(input: string): string {
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
  return output;
}

/**
 * Generate a stable placeholder for a known sensitive value.
 * Use when the value is already isolated (e.g. a credential field) and
 * you don't need pattern detection.
 */
export function obfuscateValue(
  value: string,
  category: ObfuscationCategory = "USER",
): string {
  if (!STATE.enabled || !value) return value;
  return placeholderFor(value, category);
}

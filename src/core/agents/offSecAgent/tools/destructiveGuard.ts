/**
 * Destructive-action guard — deterministic, latency-free classification of
 * tool calls that would perform irreversible / high-blast-radius operations
 * against a target (or the host), plus fail-closed enforcement.
 *
 * Motivation: a pentest routinely needs to send writes (POST/PUT/PATCH) to
 * prove authorization/IDOR flaws, so blocking *all* writes would neuter the
 * agent. What clients want gated behind an explicit opt-in is the destructive
 * subset — DB deletes/drops/truncates, API write-deletes, and catastrophic
 * host operations. This module classifies exactly that subset.
 *
 * Design: a layered pipeline of pure predicates (regex + structural rules).
 * NO LLM, NO network, NO I/O — classification is O(input length) so it adds
 * effectively zero latency on the tool-call hot path. Each rule is named so a
 * block reason is specific and debuggable.
 *
 * Two false-signal traps this deliberately avoids:
 *  - Over-blocking benign recon: a destructive keyword merely *mentioned* in a
 *    URL/path, a doc, a grepped log, or prose is NOT destructive. SQL/NoSQL in
 *    a command is only destructive when an actual DB client executes it; in an
 *    HTTP request only when it appears as a real statement/injection payload.
 *  - Under-blocking real ops: encoded payloads are decoded first, and method /
 *    delete-verb / override detection covers the common obfuscations.
 *
 * Enforcement mirrors {@link scopeGuard}: the assert helpers are a no-op when
 * destructive testing is authorized (`session.config.allowDestructiveActions
 * === true`) and otherwise throw {@link DestructiveActionError}, which the
 * `http_request` / `execute_command` tools translate into a structured, non-
 * fatal error result the model can read and route around.
 */

import type { ToolContext } from "./types";

/** Destructive category, used for the block reason + observability. */
export type DestructiveCategory =
  | "http-delete-method"
  | "http-destructive-path"
  | "sql-destructive"
  | "nosql-destructive"
  | "host-destructive";

export interface DestructiveClassification {
  destructive: boolean;
  /** Populated when `destructive` is true. */
  category?: DestructiveCategory;
  /** Stable rule id that fired (for logs / block message). */
  ruleId?: string;
  /** Human-readable explanation of what was matched. */
  reason?: string;
}

const NOT_DESTRUCTIVE: DestructiveClassification = { destructive: false };

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/**
 * Best-effort URL/form decode so percent- or `+`-encoded payloads are matched
 * the same as their plaintext form (`%2Fdelete` → `/delete`, `DROP%20TABLE` →
 * `DROP TABLE`). Runs up to two passes to unwrap double-encoding, decodes each
 * `%XX` sequence independently so a stray `%` never throws.
 */
export function safeDecode(input: string): string {
  let out = input ?? "";
  for (let pass = 0; pass < 2; pass++) {
    const decoded = out.replace(/\+/g, " ").replace(/%[0-9a-fA-F]{2}/g, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
    if (decoded === out) break;
    out = decoded;
  }
  return out;
}

// ---------------------------------------------------------------------------
// SQL / NoSQL statement patterns
// ---------------------------------------------------------------------------

/**
 * Destructive SQL DML/DDL statement head: DROP {TABLE,DATABASE,...}, TRUNCATE,
 * DELETE FROM, ALTER TABLE ... DROP. Deliberately does NOT match
 * INSERT/UPDATE/SELECT — ordinary writes stay allowed.
 */
const SQL_DESTRUCTIVE_STATEMENT =
  /(?:drop\s+(?:table|database|schema|index|view|column|role|user|sequence|trigger|function|procedure)|truncate\s+(?:table\s+)?[`"\w]|delete\s+from\s+[`"\w]|alter\s+table\s+[^;]*\bdrop\b)/i;

/** The statement is the (trimmed) start of the payload — a raw-SQL body. */
const SQL_STATEMENT_START = new RegExp(
  `^\\s*['"\`;)\\s]*(?:${SQL_DESTRUCTIVE_STATEMENT.source})`,
  "i",
);

/** Classic SQLi break: a quote (and/or `;`) immediately preceding the statement. */
const SQL_INJECTION_CONTEXT = new RegExp(
  `['"\`]\\s*;?\\s*(?:${SQL_DESTRUCTIVE_STATEMENT.source})|;\\s*(?:${SQL_DESTRUCTIVE_STATEMENT.source})`,
  "i",
);

/**
 * Destructive SQL carried in an HTTP request. Requires the statement to look
 * like an actual statement or injection payload — a raw statement at the start,
 * or a statement right after a SQLi break (`'`, `"`, `;`) — so prose or JSON
 * that merely mentions "delete from" / "drop table" is not flagged.
 */
function httpCarriesDestructiveSql(decoded: string): boolean {
  if (!SQL_DESTRUCTIVE_STATEMENT.test(decoded)) return false;
  return (
    SQL_STATEMENT_START.test(decoded) || SQL_INJECTION_CONTEXT.test(decoded)
  );
}

/**
 * Destructive NoSQL / cache operation in an HTTP body. Structured call forms
 * (`db.x.drop()`, `dropDatabase(`, `deleteMany(`) or a Redis flush issued as a
 * command line (start-of-body / after `;`/newline) — not a bare word buried in
 * a path or prose.
 */
const NOSQL_HTTP_DESTRUCTIVE =
  /\bdb(?:\.\w+)+\.(?:drop(?:Database)?|deleteMany|remove)\s*\(|\.dropDatabase\s*\(|\.drop\s*\(\s*\)|\bdeleteMany\s*\(\s*\{|(?:^|[\n;])\s*(?:flushall|flushdb)\b/i;

/** Destructive NoSQL / cache op in a shell command (paired with a DB client). */
const NOSQL_CMD_DESTRUCTIVE =
  /\bdb(?:\.\w+)*\.(?:drop(?:Database)?|deleteMany|remove)\s*\(|\.dropDatabase\s*\(|\.drop\s*\(\s*\)|\bflushall\b|\bflushdb\b/i;

// ---------------------------------------------------------------------------
// HTTP method / path / override
// ---------------------------------------------------------------------------

/** Write methods that become destructive when aimed at a delete/destroy route. */
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH"]);

/**
 * Path/query segments that signal an intent to delete or wipe. Word-bounded so
 * `/deleted-items` (a listing) does not match while `/users/1/delete` does.
 * Run against the DECODED url.
 */
const DESTRUCTIVE_PATH_PATTERN =
  /(?:^|[/_?&=.-])(?:delete|destroy|drop|purge|truncate|wipe|obliterate|nuke|remove|hard[-_]?delete|force[-_]?delete)(?:[/_?&=.-]|$)/i;

/**
 * Method-override to DELETE via header, query, or body — covers the common
 * override header spellings (`X-HTTP-Method-Override`, `X-HTTP-Method`,
 * `X-Method-Override`, `X-Method`) plus `_method` / `httpMethod` params.
 */
const METHOD_OVERRIDE_DELETE_PATTERN =
  /(?:_method|x-http-method-override|x-http-method|x-method-override|x-method|httpmethod)\s*[=:]\s*['"]?delete\b/i;

// ---------------------------------------------------------------------------
// Host-destructive command rules (anchored to command position, not substring)
// ---------------------------------------------------------------------------

/** Start of a command word: line start, or after a shell separator. */
const CMD_BOUNDARY = String.raw`(?:^|[\n;&|]|&&|\|\|)\s*(?:sudo\s+)?`;

/**
 * `rm` with BOTH recursive and force semantics (flags in any order, combined or
 * split) aimed at a filesystem root, home, or system dir — or with
 * `--no-preserve-root`. Ordinary sandbox scratch cleanup (`rm -rf /tmp/x`,
 * `rm -rf ./build`) does NOT match.
 */
export function isDangerousRm(command: string): boolean {
  const rmRe = /\brm\b([^\n;|&]*)/gi;
  for (const match of command.matchAll(rmRe)) {
    const args = match[1] ?? "";
    const hasRecursive = /(?:^|\s)(?:-[a-z]*r[a-z]*|--recursive)\b/i.test(args);
    const hasForce = /(?:^|\s)(?:-[a-z]*f[a-z]*|--force)\b/i.test(args);
    if (!hasRecursive || !hasForce) continue;
    if (/--no-preserve-root/i.test(args)) return true;
    for (const rawToken of args.split(/\s+/)) {
      if (!rawToken || rawToken.startsWith("-")) continue;
      const token = rawToken.replace(/^['"]|['"]$/g, "");
      // Root / wildcard-root / home shorthands.
      if (/^(?:\/|\/\*|~|\$HOME|\$\{HOME\})$/.test(token)) return true;
      if (/^(?:~|\$HOME|\$\{HOME\})\//.test(token)) return true;
      // A system or home directory, with or without a subpath.
      if (
        /^\/(?:etc|var|usr|bin|sbin|boot|lib|lib64|root|home|opt|srv|sys|proc|dev)(?:\/|$)/i.test(
          token,
        )
      ) {
        return true;
      }
    }
  }
  return false;
}

const HOST_DESTRUCTIVE_RULES: Array<{
  id: string;
  test: (command: string) => boolean;
}> = [
  { id: "rm-rf-root", test: isDangerousRm },
  // Raw block-device write / disk imaging.
  {
    id: "dd-to-device",
    test: (c) =>
      new RegExp(
        `${CMD_BOUNDARY}dd\\b[^\\n;|&]*\\bof=\\s*['"]?/dev/`,
        "i",
      ).test(c),
  },
  // Filesystem creation over a device.
  {
    id: "mkfs",
    test: (c) =>
      new RegExp(`${CMD_BOUNDARY}(?:/s?bin/)?mkfs(?:\\.\\w+)?\\b`, "i").test(c),
  },
  // Redirect into a block device.
  {
    id: "clobber-device",
    test: (c) => />\s*['"]?\/dev\/(?:sd|nvme|hd|mapper|disk)/i.test(c),
  },
  // Classic fork bomb.
  {
    id: "fork-bomb",
    test: (c) => /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(c),
  },
  // Power-state changes — only as an executed command, not a URL/path token.
  {
    id: "power-state",
    test: (c) =>
      new RegExp(
        `${CMD_BOUNDARY}(?:/(?:usr/)?s?bin/)?(?:shutdown|reboot|halt|poweroff)\\b`,
        "i",
      ).test(c) || new RegExp(`${CMD_BOUNDARY}init\\s+0\\b`, "i").test(c),
  },
];

// ---------------------------------------------------------------------------
// HTTP-in-command detection
// ---------------------------------------------------------------------------

const HTTP_CLIENT_PATTERN = /\b(?:curl|wget|xh|httpie)\b/i;
const URL_IN_COMMAND = /https?:\/\/[^\s"'`;|&)<>]+/gi;

/** `-X DELETE`, `-XDELETE`, `--request=DELETE`, `--method delete`. */
const CURL_DELETE = /(?:-X|--request|--method)[=\s]*['"]?delete\b/i;

/** httpie/xh positional method: `http DELETE url`, `xh delete url` (at cmd pos). */
const HTTPIE_METHOD = new RegExp(
  `${CMD_BOUNDARY}(?:https?|xh|httpie)\\s+(?:-{1,2}\\S+\\s+)*(delete|post|put|patch)\\b`,
  "i",
);
const CURL_WRITE_METHOD =
  /(?:-X|--request|--method)[=\s]*['"]?(?:post|put|patch)\b/i;
const CURL_DATA_FLAG =
  /(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode|-ascii)?|-F|--form|--json)\b/i;

/**
 * In-script HTTP DELETE nested inside `execute_command` (Node/Bun/Deno,
 * Playwright, ts-node, etc.) — the path apex's http_request-level controls and
 * the curl-based detection above both miss. The reliable signal is a DELETE
 * method on an HTTP call, NOT the URL: the dangerous path is frequently built
 * dynamically (`fetch(`/api/x/${id}`, …)` where `id` resolves to `undefined`),
 * so it never contains a literal delete keyword.
 *
 * Two forms:
 *  - a request-options object carrying `method: 'DELETE'` (fetch / axios config
 *    / Playwright request options), paired with an HTTP-client token so a grep
 *    for the literal string is not misclassified; and
 *  - a positional client delete call (`axios.delete(`, `page.request.delete(`).
 */
const JS_METHOD_DELETE = /\bmethod\s*:\s*['"`]?\s*delete\b/i;
const JS_HTTP_CLIENT_HINT =
  /\b(?:fetch|axios|got|ky|superagent|needle|node-fetch|undici|phin|XMLHttpRequest|xhr)\b|\.\s*(?:request|open)\s*\(/i;
const JS_CLIENT_DELETE_CALL =
  /\b(?:axios|got|ky|superagent|needle|supertest|phin|page|apiContext|apiRequestContext|request)\s*(?:\.\s*\w+)*\.\s*delete\s*\(/i;

/** Classify an HTTP call expressed as a shell command (curl/wget/httpie/xh, or an in-script fetch/axios). */
function classifyCommandHttp(command: string): DestructiveClassification {
  const decoded = safeDecode(command);

  // Explicit DELETE via flag or httpie positional method.
  const httpieMethod = HTTPIE_METHOD.exec(command)?.[1]?.toLowerCase();
  if (CURL_DELETE.test(command) || httpieMethod === "delete") {
    return {
      destructive: true,
      category: "http-delete-method",
      ruleId: "cmd-http-delete",
      reason: "command issues an HTTP DELETE against the target",
    };
  }

  // In-script HTTP DELETE (fetch/axios/Playwright) run via a JS runtime.
  if (
    (JS_METHOD_DELETE.test(command) && JS_HTTP_CLIENT_HINT.test(command)) ||
    JS_CLIENT_DELETE_CALL.test(command)
  ) {
    return {
      destructive: true,
      category: "http-delete-method",
      ruleId: "cmd-script-http-delete",
      reason:
        "command runs an in-script HTTP DELETE (fetch/axios/Playwright) against the target",
    };
  }

  // Method-override to DELETE carried in headers/data.
  if (METHOD_OVERRIDE_DELETE_PATTERN.test(decoded)) {
    return {
      destructive: true,
      category: "http-delete-method",
      ruleId: "cmd-http-override-delete",
      reason: "command overrides the HTTP method to DELETE",
    };
  }

  // A write request to a delete/destroy route.
  const writeIndicated =
    CURL_WRITE_METHOD.test(command) ||
    CURL_DATA_FLAG.test(command) ||
    httpieMethod === "post" ||
    httpieMethod === "put" ||
    httpieMethod === "patch";
  if (HTTP_CLIENT_PATTERN.test(command) && writeIndicated) {
    for (const rawUrl of command.match(URL_IN_COMMAND) ?? []) {
      if (DESTRUCTIVE_PATH_PATTERN.test(safeDecode(rawUrl))) {
        return {
          destructive: true,
          category: "http-destructive-path",
          ruleId: "cmd-http-destructive-path",
          reason:
            "command sends a write request to a delete/destroy/purge route",
        };
      }
    }
  }

  return NOT_DESTRUCTIVE;
}

const DB_CLIENT_PATTERN =
  /\b(?:psql|mysql|mariadb|mongosh|mongo|sqlite3|sqlcmd|sqlplus|cqlsh|clickhouse-client|redis-cli|sqlmap)\b|\bcockroach\s+sql\b/i;

// ---------------------------------------------------------------------------
// Classifiers (pure)
// ---------------------------------------------------------------------------

/**
 * Classify an HTTP request. `body` is only inspected when it is a string;
 * `headers` are folded in so a method-override header is caught. URL and body
 * are decoded first so encoded payloads are matched.
 */
export function classifyHttpAction(input: {
  method: string;
  url: string;
  body?: unknown;
  headers?: Record<string, unknown>;
}): DestructiveClassification {
  const method = input.method.toUpperCase();
  const decodedUrl = safeDecode(input.url);
  const decodedBody = safeDecode(
    typeof input.body === "string" ? input.body : "",
  );
  const headerText = input.headers
    ? Object.entries(input.headers)
        .map(([name, value]) => `${name}: ${String(value)}`)
        .join("\n")
    : "";
  const overrideHaystack = `${decodedUrl}\n${decodedBody}\n${headerText}`;

  // The DELETE verb is the canonical "API write-delete".
  if (method === "DELETE") {
    return {
      destructive: true,
      category: "http-delete-method",
      ruleId: "http-method-delete",
      reason: "HTTP DELETE removes a resource on the target",
    };
  }

  // Method-override to DELETE — honored by some stacks regardless of the verb.
  if (METHOD_OVERRIDE_DELETE_PATTERN.test(overrideHaystack)) {
    return {
      destructive: true,
      category: "http-delete-method",
      ruleId: "http-method-override-delete",
      reason: "request overrides the HTTP method to DELETE",
    };
  }

  // Raw destructive SQL as a statement / injection payload in url or body.
  if (httpCarriesDestructiveSql(`${decodedUrl}\n${decodedBody}`)) {
    return {
      destructive: true,
      category: "sql-destructive",
      ruleId: "http-body-sql",
      reason:
        "request carries a destructive SQL statement (DROP/TRUNCATE/DELETE FROM/ALTER…DROP)",
    };
  }

  // Structured destructive NoSQL/cache op in the body.
  if (NOSQL_HTTP_DESTRUCTIVE.test(decodedBody)) {
    return {
      destructive: true,
      category: "nosql-destructive",
      ruleId: "http-body-nosql",
      reason:
        "request carries a destructive NoSQL/cache operation (drop/deleteMany/flush)",
    };
  }

  // A write method aimed at a delete/destroy route.
  if (WRITE_METHODS.has(method) && DESTRUCTIVE_PATH_PATTERN.test(decodedUrl)) {
    return {
      destructive: true,
      category: "http-destructive-path",
      ruleId: "http-destructive-path",
      reason: "write request targets a delete/destroy/purge route",
    };
  }

  return NOT_DESTRUCTIVE;
}

/** Classify a shell command string. */
export function classifyCommandAction(
  command: string,
): DestructiveClassification {
  for (const { id, test } of HOST_DESTRUCTIVE_RULES) {
    if (test(command)) {
      return {
        destructive: true,
        category: "host-destructive",
        ruleId: id,
        reason: `command performs a catastrophic host operation (${id})`,
      };
    }
  }

  // SQL/NoSQL is destructive only when an actual DB client executes it — a
  // grep/cat/echo that merely contains "DROP TABLE" or "FLUSHALL" is recon.
  if (DB_CLIENT_PATTERN.test(command)) {
    if (SQL_DESTRUCTIVE_STATEMENT.test(command)) {
      return {
        destructive: true,
        category: "sql-destructive",
        ruleId: "cmd-sql",
        reason:
          "command runs a destructive SQL statement via a DB client (DROP/TRUNCATE/DELETE FROM/ALTER…DROP)",
      };
    }
    if (NOSQL_CMD_DESTRUCTIVE.test(command)) {
      return {
        destructive: true,
        category: "nosql-destructive",
        ruleId: "cmd-nosql",
        reason:
          "command runs a destructive NoSQL/cache operation via a DB client (drop/deleteMany/flush)",
      };
    }
  }

  return classifyCommandHttp(command);
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

export class DestructiveActionError extends Error {
  constructor(
    public readonly classification: DestructiveClassification,
    subject: string,
  ) {
    super(
      `Destructive action blocked: ${subject} — ${classification.reason ?? "destructive operation"}. ` +
        `Destructive testing (DB deletes/drops, API write-deletes, catastrophic host operations) is NOT authorized for this engagement. ` +
        `Prove the flaw without completing the destructive step (e.g. demonstrate the authorization boundary is crossed with a read or a reversible action), or ask the operator to enable destructive testing.`,
    );
    this.name = "DestructiveActionError";
  }
}

/**
 * True when the caller has explicitly authorized destructive testing. Absent /
 * false → destructive actions are blocked (fail-closed, off by default).
 */
export function isDestructiveTestingAllowed(ctx: ToolContext): boolean {
  return ctx.session?.config?.allowDestructiveActions === true;
}

/**
 * Assert an HTTP request is permitted. No-op when destructive testing is
 * authorized; otherwise throws {@link DestructiveActionError} for a
 * destructive-classified request.
 *
 * `http_request` calls this on the FULLY-RESOLVED request (after any
 * prompt-injection ref in the body expands to a concrete string), so a resolved
 * payload carrying destructive SQL/NoSQL is classified before the request is
 * sent. `body` is only inspected when it is a string.
 */
export function assertHttpActionAllowed(
  input: {
    method: string;
    url: string;
    body?: unknown;
    headers?: Record<string, unknown>;
  },
  ctx: ToolContext,
): void {
  if (isDestructiveTestingAllowed(ctx)) return;
  const classification = classifyHttpAction(input);
  if (classification.destructive) {
    throw new DestructiveActionError(
      classification,
      `${input.method.toUpperCase()} ${input.url}`,
    );
  }
}

/**
 * Assert a shell command is permitted. No-op when destructive testing is
 * authorized; otherwise throws {@link DestructiveActionError} for a
 * destructive-classified command.
 */
export function assertCommandActionAllowed(
  command: string,
  ctx: ToolContext,
): void {
  if (isDestructiveTestingAllowed(ctx)) return;
  const classification = classifyCommandAction(command);
  if (classification.destructive) {
    throw new DestructiveActionError(classification, command);
  }
}

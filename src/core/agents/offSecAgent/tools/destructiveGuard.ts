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
// Pattern layers
// ---------------------------------------------------------------------------

/**
 * Destructive SQL DML/DDL. Matches the statement kinds that delete or
 * irreversibly reshape data: DROP {TABLE,DATABASE,SCHEMA,...}, TRUNCATE,
 * DELETE FROM, and ALTER TABLE ... DROP. Deliberately does NOT match
 * INSERT/UPDATE/SELECT — ordinary writes stay allowed. Applied to shell
 * commands (psql/mysql/sqlite3 -c "...", sqlmap --sql-query, etc.) and to
 * HTTP bodies/URLs (raw-SQL and SQLi payloads).
 */
const SQL_DESTRUCTIVE_PATTERN =
  /\b(?:drop\s+(?:table|database|schema|index|view|column|role|user|sequence|trigger|function|procedure)|truncate\s+(?:table\s+)?[`"\w]|delete\s+from\s+[`"\w]|alter\s+table\s+[^;]*\bdrop\b)/i;

/**
 * Destructive NoSQL / cache operations. Mongo collection/database drops and
 * mass deletes; Redis flushes and pattern deletes. Applied to shell commands
 * (mongosh --eval, redis-cli ...) and HTTP bodies.
 */
const NOSQL_DESTRUCTIVE_PATTERN =
  /(?:\bdb(?:\.\w+)*\.(?:drop(?:Database)?|deleteMany|remove)\s*\(|\.drop\s*\(\s*\)|\bflushall\b|\bflushdb\b)/i;

/**
 * Catastrophic host operations that are never a legitimate, reversible step in
 * a black-box test. Narrowly targeted so ordinary sandbox scratch use (e.g.
 * `rm -rf /tmp/apex-xxx`) does NOT match — only root/home wipes, raw-device
 * writes, filesystem creation, fork bombs, and power state changes.
 */
const HOST_DESTRUCTIVE_PATTERNS: Array<{ id: string; re: RegExp }> = [
  // rm -rf targeting a filesystem root, home, or wildcard root (`/`, `/*`,
  // `~`, `$HOME`, `/etc`, `/var`, `/home/ubuntu`, ...). The recursive and force
  // flags may appear in any order, combined (`-rf`/`-fr`), split (`-r -f`), or
  // long-form (`--recursive --force`), interleaved with other flags such as
  // `--no-preserve-root`; sensitive prefixes match with or without a subpath.
  {
    id: "rm-rf-root",
    re: /\brm\s+(?=(?:-\S+\s+)*(?:-\w*r\w*|--recursive))(?=(?:-\S+\s+)*(?:-\w*f\w*|--force))(?:-\S+\s+)*(?:--\s+)?(?:['"]?(?:\/(?:\*|(?:etc|var|usr|bin|boot|lib|root|home|sys|proc|dev)(?:\/\S*)?)?|~|\$HOME)(?:['"\s/]|$))/i,
  },
  // Raw block-device write / disk imaging.
  { id: "dd-to-device", re: /\bdd\b[^\n;|&]*\bof=\s*['"]?\/dev\//i },
  // Filesystem creation over an existing device.
  { id: "mkfs", re: /\bmkfs(?:\.\w+)?\s+/i },
  // Redirect into a block device.
  { id: "clobber-device", re: />\s*['"]?\/dev\/(?:sd|nvme|hd|mapper|disk)/i },
  // Classic fork bomb.
  { id: "fork-bomb", re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/ },
  // Power-state changes.
  { id: "power-state", re: /\b(?:shutdown|reboot|halt|poweroff|init\s+0)\b/i },
];

/**
 * HTTP write methods that are not themselves destructive but become so when
 * the path/query signals a delete/destroy/purge intent (covers REST delete
 * endpoints reached via POST, method-override, and GraphQL-style delete
 * mutation routes).
 */
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH"]);

/**
 * Path/query segments that signal an intent to delete or wipe. Word-bounded so
 * `/deleted-items` (a listing) does not match while `/users/1/delete` does.
 */
const DESTRUCTIVE_PATH_PATTERN =
  /(?:^|[/_?&=.-])(?:delete|destroy|drop|purge|truncate|wipe|obliterate|nuke|remove|hard[-_]?delete|force[-_]?delete)(?:[/_?&=.-]|$)/i;

/** Method-override to DELETE via header/query/body (e.g. `?_method=DELETE`). */
const METHOD_OVERRIDE_DELETE_PATTERN =
  /(?:_method|x-http-method-override|httpmethod)\s*[=:]\s*['"]?delete\b/i;

// ---------------------------------------------------------------------------
// Classifiers (pure)
// ---------------------------------------------------------------------------

/**
 * Classify an HTTP request. `body` is only inspected when it is a string.
 * `headers` are folded into the haystack as `name: value` lines so a
 * method-override header (e.g. `X-HTTP-Method-Override: DELETE`) is caught.
 */
export function classifyHttpAction(input: {
  method: string;
  url: string;
  body?: unknown;
  headers?: Record<string, unknown>;
}): DestructiveClassification {
  const method = input.method.toUpperCase();
  const bodyText = typeof input.body === "string" ? input.body : "";
  const headerText = input.headers
    ? Object.entries(input.headers)
        .map(([name, value]) => `${name}: ${String(value)}`)
        .join("\n")
    : "";
  const haystack = `${input.url}\n${bodyText}\n${headerText}`;

  // Raw destructive SQL / NoSQL carried in the URL or body (SQLi payloads,
  // admin/query endpoints) — destructive regardless of method.
  if (SQL_DESTRUCTIVE_PATTERN.test(haystack)) {
    return {
      destructive: true,
      category: "sql-destructive",
      ruleId: "http-body-sql",
      reason:
        "request carries a destructive SQL statement (DROP/TRUNCATE/DELETE FROM/ALTER…DROP)",
    };
  }
  if (NOSQL_DESTRUCTIVE_PATTERN.test(haystack)) {
    return {
      destructive: true,
      category: "nosql-destructive",
      ruleId: "http-body-nosql",
      reason:
        "request carries a destructive NoSQL/cache operation (drop/deleteMany/flush)",
    };
  }

  // The DELETE verb is the canonical "API write-delete".
  if (method === "DELETE") {
    return {
      destructive: true,
      category: "http-delete-method",
      ruleId: "http-method-delete",
      reason: "HTTP DELETE removes a resource on the target",
    };
  }

  // A write method aimed at a delete/destroy route, or overriding to DELETE.
  if (WRITE_METHODS.has(method)) {
    if (METHOD_OVERRIDE_DELETE_PATTERN.test(haystack)) {
      return {
        destructive: true,
        category: "http-delete-method",
        ruleId: "http-method-override-delete",
        reason: "write request overrides the method to DELETE",
      };
    }
    if (DESTRUCTIVE_PATH_PATTERN.test(input.url)) {
      return {
        destructive: true,
        category: "http-destructive-path",
        ruleId: "http-destructive-path",
        reason: "write request targets a delete/destroy/purge route",
      };
    }
  }

  return NOT_DESTRUCTIVE;
}

/** Classify a shell command string. */
export function classifyCommandAction(
  command: string,
): DestructiveClassification {
  for (const { id, re } of HOST_DESTRUCTIVE_PATTERNS) {
    if (re.test(command)) {
      return {
        destructive: true,
        category: "host-destructive",
        ruleId: id,
        reason: `command performs a catastrophic host operation (${id})`,
      };
    }
  }

  if (SQL_DESTRUCTIVE_PATTERN.test(command)) {
    return {
      destructive: true,
      category: "sql-destructive",
      ruleId: "cmd-sql",
      reason:
        "command runs a destructive SQL statement (DROP/TRUNCATE/DELETE FROM/ALTER…DROP)",
    };
  }
  if (NOSQL_DESTRUCTIVE_PATTERN.test(command)) {
    return {
      destructive: true,
      category: "nosql-destructive",
      ruleId: "cmd-nosql",
      reason:
        "command runs a destructive NoSQL/cache operation (drop/deleteMany/flush)",
    };
  }

  // curl/wget issuing an HTTP DELETE against the target.
  if (
    /(?:^|[;&|]|\s)(?:curl|wget|http|xh|httpie)\b[^\n]*(?:-X|--request|--method)[=\s]+['"]?delete\b/i.test(
      command,
    )
  ) {
    return {
      destructive: true,
      category: "http-delete-method",
      ruleId: "cmd-http-delete",
      reason: "command issues an HTTP DELETE against the target",
    };
  }

  return NOT_DESTRUCTIVE;
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

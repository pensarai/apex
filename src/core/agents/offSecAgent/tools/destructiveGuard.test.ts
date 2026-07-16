import { describe, expect, it } from "vitest";
import type { SessionConfig, SessionInfo } from "../../../session";
import {
  assertCommandActionAllowed,
  assertHttpActionAllowed,
  classifyCommandAction,
  classifyHttpAction,
  DestructiveActionError,
  isDestructiveTestingAllowed,
} from "./destructiveGuard";
import type { ToolContext } from "./types";

function makeCtx(config: Partial<SessionConfig> = {}): ToolContext {
  return {
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
      config,
    } as SessionInfo,
    agentCwd: "/tmp/test",
  };
}

// ---------------------------------------------------------------------------
// classifyHttpAction
// ---------------------------------------------------------------------------

describe("classifyHttpAction", () => {
  it("flags HTTP DELETE as an API write-delete", () => {
    const c = classifyHttpAction({
      method: "DELETE",
      url: "https://api.example.com/users/42",
    });
    expect(c.destructive).toBe(true);
    expect(c.category).toBe("http-delete-method");
  });

  it("is case-insensitive on the method", () => {
    expect(
      classifyHttpAction({ method: "delete", url: "https://x.com/a" })
        .destructive,
    ).toBe(true);
  });

  it("allows ordinary reads and writes", () => {
    expect(
      classifyHttpAction({ method: "GET", url: "https://x.com/users/1" })
        .destructive,
    ).toBe(false);
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/users",
        body: '{"name":"a"}',
      }).destructive,
    ).toBe(false);
    expect(
      classifyHttpAction({
        method: "PUT",
        url: "https://x.com/users/1",
        body: '{"displayName":"new"}',
      }).destructive,
    ).toBe(false);
  });

  it("flags a write method aimed at a delete/destroy route", () => {
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/users/1/delete",
      }).destructive,
    ).toBe(true);
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/account/destroy",
      }).category,
    ).toBe("http-destructive-path");
    expect(
      classifyHttpAction({ method: "PATCH", url: "https://x.com/db/purge" })
        .destructive,
    ).toBe(true);
  });

  it("does not flag a listing route that merely contains 'deleted'", () => {
    expect(
      classifyHttpAction({ method: "POST", url: "https://x.com/deleted-items" })
        .destructive,
    ).toBe(false);
    expect(
      classifyHttpAction({ method: "GET", url: "https://x.com/users/1/delete" })
        .destructive,
    ).toBe(false);
  });

  it("flags a method-override to DELETE", () => {
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/users/1?_method=DELETE",
      }).destructive,
    ).toBe(true);
  });

  it("flags a method-override to DELETE via header", () => {
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/users/1",
        headers: { "X-HTTP-Method-Override": "DELETE" },
      }).destructive,
    ).toBe(true);
  });

  it("flags destructive SQL in the body regardless of method", () => {
    const c = classifyHttpAction({
      method: "POST",
      url: "https://x.com/graphql",
      body: 'mutation { raw(q: "DROP TABLE users") }',
    });
    expect(c.destructive).toBe(true);
    expect(c.category).toBe("sql-destructive");
  });

  it("flags a destructive SQLi payload in the query string", () => {
    expect(
      classifyHttpAction({
        method: "GET",
        url: "https://x.com/p?id=1;DROP TABLE sessions--",
      }).destructive,
    ).toBe(true);
  });

  it("flags destructive NoSQL/cache operations in the body", () => {
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/admin/eval",
        body: "db.users.drop()",
      }).category,
    ).toBe("nosql-destructive");
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/admin/eval",
        body: "FLUSHALL",
      }).destructive,
    ).toBe(true);
  });

  it("ignores non-string bodies (e.g. prompt-injection refs)", () => {
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/chat",
        body: { kind: "prompt_injection_ref", id: "abc" },
      }).destructive,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// classifyCommandAction
// ---------------------------------------------------------------------------

describe("classifyCommandAction", () => {
  it("flags destructive SQL run through a db client", () => {
    expect(
      classifyCommandAction('psql -h db.example.com -c "DROP TABLE users"')
        .category,
    ).toBe("sql-destructive");
    expect(
      classifyCommandAction('mysql -e "TRUNCATE TABLE sessions"').destructive,
    ).toBe(true);
    expect(
      classifyCommandAction('sqlite3 app.db "DELETE FROM audit_log"')
        .destructive,
    ).toBe(true);
  });

  it("flags destructive NoSQL/cache operations", () => {
    expect(
      classifyCommandAction("redis-cli -h cache FLUSHALL").destructive,
    ).toBe(true);
    expect(
      classifyCommandAction('mongosh --eval "db.dropDatabase()"').category,
    ).toBe("nosql-destructive");
  });

  it("flags an HTTP DELETE issued via curl/wget", () => {
    expect(
      classifyCommandAction("curl -X DELETE https://x.com/users/1").category,
    ).toBe("http-delete-method");
    expect(
      classifyCommandAction("curl --request delete https://x.com/a")
        .destructive,
    ).toBe(true);
  });

  it("flags catastrophic host operations", () => {
    expect(classifyCommandAction("rm -rf /").destructive).toBe(true);
    expect(classifyCommandAction("rm -rf ~").destructive).toBe(true);
    expect(classifyCommandAction("rm -rf /etc").category).toBe(
      "host-destructive",
    );
    expect(classifyCommandAction("mkfs.ext4 /dev/sda1").destructive).toBe(true);
    expect(
      classifyCommandAction("dd if=/dev/zero of=/dev/sda").destructive,
    ).toBe(true);
    expect(classifyCommandAction("sudo reboot").destructive).toBe(true);
  });

  it("allows ordinary recon / scratch commands", () => {
    expect(classifyCommandAction("curl -i https://x.com/").destructive).toBe(
      false,
    );
    expect(
      classifyCommandAction("curl -X POST -d 'a=1' https://x.com/login")
        .destructive,
    ).toBe(false);
    expect(classifyCommandAction("nmap -sV -p- example.com").destructive).toBe(
      false,
    );
    // Sandbox scratch cleanup must not be classed as catastrophic.
    expect(
      classifyCommandAction("rm -rf /tmp/apex-scratch-123").destructive,
    ).toBe(false);
    expect(
      classifyCommandAction('sqlmap -u "https://x.com/p?id=1" --batch')
        .destructive,
    ).toBe(false);
    // A read-oriented SELECT is not destructive.
    expect(
      classifyCommandAction('psql -c "SELECT * FROM users LIMIT 1"')
        .destructive,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

describe("isDestructiveTestingAllowed", () => {
  it("is false by default (fail-closed)", () => {
    expect(isDestructiveTestingAllowed(makeCtx())).toBe(false);
    expect(
      isDestructiveTestingAllowed(makeCtx({ allowDestructiveActions: false })),
    ).toBe(false);
  });
  it("is true only when explicitly enabled", () => {
    expect(
      isDestructiveTestingAllowed(makeCtx({ allowDestructiveActions: true })),
    ).toBe(true);
  });
});

describe("assertHttpActionAllowed", () => {
  it("throws for a destructive request when not authorized", () => {
    expect(() =>
      assertHttpActionAllowed(
        { method: "DELETE", url: "https://x.com/a" },
        makeCtx(),
      ),
    ).toThrow(DestructiveActionError);
  });

  it("is a no-op for a destructive request when authorized", () => {
    expect(() =>
      assertHttpActionAllowed(
        { method: "DELETE", url: "https://x.com/a" },
        makeCtx({ allowDestructiveActions: true }),
      ),
    ).not.toThrow();
  });

  it("is a no-op for a non-destructive request", () => {
    expect(() =>
      assertHttpActionAllowed(
        { method: "GET", url: "https://x.com/a" },
        makeCtx(),
      ),
    ).not.toThrow();
  });
});

describe("assertCommandActionAllowed", () => {
  it("throws for a destructive command when not authorized", () => {
    expect(() =>
      assertCommandActionAllowed('psql -c "DROP TABLE t"', makeCtx()),
    ).toThrow(DestructiveActionError);
  });

  it("is a no-op when authorized", () => {
    expect(() =>
      assertCommandActionAllowed(
        'psql -c "DROP TABLE t"',
        makeCtx({ allowDestructiveActions: true }),
      ),
    ).not.toThrow();
  });

  it("is a no-op for a benign command", () => {
    expect(() =>
      assertCommandActionAllowed("curl -i https://x.com/", makeCtx()),
    ).not.toThrow();
  });
});

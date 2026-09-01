import { describe, expect, it } from "vitest";
import type { SessionConfig, SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
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
    subagentSpawner: inProcessSubagentSpawner,
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

  it("flags method-override to DELETE via alternate header spellings", () => {
    for (const name of [
      "X-HTTP-Method-Override",
      "X-HTTP-Method",
      "X-Method-Override",
      "X-Method",
    ]) {
      expect(
        classifyHttpAction({
          method: "POST",
          url: "https://x.com/users/1",
          headers: { [name]: "DELETE" },
        }).destructive,
      ).toBe(true);
    }
  });

  it("flags a GET that overrides the method to DELETE (some stacks honor it)", () => {
    expect(
      classifyHttpAction({
        method: "GET",
        url: "https://x.com/users/1?_method=DELETE",
      }).destructive,
    ).toBe(true);
    expect(
      classifyHttpAction({
        method: "GET",
        url: "https://x.com/users/1",
        headers: { "X-HTTP-Method-Override": "DELETE" },
      }).destructive,
    ).toBe(true);
  });

  it("flags a write to a percent-encoded delete route", () => {
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/users/1%2Fdelete",
      }).category,
    ).toBe("http-destructive-path");
  });

  it("flags percent-encoded destructive SQLi payloads", () => {
    expect(
      classifyHttpAction({
        method: "GET",
        url: "https://x.com/p?id=1%3B%20DROP%20TABLE%20sessions%2D%2D",
      }).category,
    ).toBe("sql-destructive");
  });

  it("does not flag SQL keywords used in natural-language / JSON prose", () => {
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/feedback",
        body: '{"message":"Please delete from my account and drop table tennis from the amenities list"}',
      }).destructive,
    ).toBe(false);
  });

  it("does not flag NoSQL keywords merely mentioned in a read path", () => {
    expect(
      classifyHttpAction({ method: "GET", url: "https://x.com/docs/flushall" })
        .destructive,
    ).toBe(false);
    expect(
      classifyHttpAction({
        method: "POST",
        url: "https://x.com/search",
        body: '{"q":"how do I run flushall safely"}',
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

  it("flags glued and alternate HTTP DELETE command forms", () => {
    expect(
      classifyCommandAction("curl -XDELETE https://x.com/a").destructive,
    ).toBe(true);
    expect(
      classifyCommandAction("curl --request=DELETE https://x.com/a")
        .destructive,
    ).toBe(true);
    // httpie / xh positional method verb.
    expect(
      classifyCommandAction("http DELETE https://x.com/a").destructive,
    ).toBe(true);
    expect(classifyCommandAction("xh delete https://x.com/a").destructive).toBe(
      true,
    );
    // Method-override header carried on a command.
    expect(
      classifyCommandAction(
        'curl -X POST -H "X-HTTP-Method-Override: DELETE" https://x.com/a',
      ).destructive,
    ).toBe(true);
  });

  it("flags a curl write to a delete/destroy route", () => {
    expect(
      classifyCommandAction("curl -X POST https://x.com/users/1/delete")
        .category,
    ).toBe("http-destructive-path");
    expect(
      classifyCommandAction("curl -d 'x=1' https://x.com/account/destroy")
        .destructive,
    ).toBe(true);
  });

  it("flags rm -rf variants that wipe a root/home/system dir", () => {
    expect(classifyCommandAction("rm -r -f /").destructive).toBe(true);
    expect(classifyCommandAction("rm --recursive --force /").destructive).toBe(
      true,
    );
    expect(
      classifyCommandAction("rm --no-preserve-root -rf /").destructive,
    ).toBe(true);
    expect(classifyCommandAction("rm -rf /home/ubuntu").destructive).toBe(true);
    expect(classifyCommandAction("rm -fr ~/").destructive).toBe(true);
    expect(classifyCommandAction("rm -rf $HOME").destructive).toBe(true);
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

  it("does not flag SQL/NoSQL keywords in recon (no DB client executing them)", () => {
    // Grepping logs/config for destructive keywords is recon, not a DB op.
    expect(
      classifyCommandAction('grep -r "DROP TABLE" /var/log/app').destructive,
    ).toBe(false);
    expect(
      classifyCommandAction("cat dump.sql | grep -i 'delete from'").destructive,
    ).toBe(false);
    expect(
      classifyCommandAction('echo "run FLUSHALL to reset" >> notes.txt')
        .destructive,
    ).toBe(false);
  });

  it("does not flag delete/power-state keywords appearing only in a URL/path", () => {
    // 'reboot' / 'shutdown' in a request path is not a host power action.
    expect(
      classifyCommandAction("curl -i https://x.com/admin/reboot").destructive,
    ).toBe(false);
    expect(
      classifyCommandAction("curl -i https://x.com/system/shutdown-status")
        .destructive,
    ).toBe(false);
    // A GET to a delete-ish path (no write) is not classified destructive.
    expect(
      classifyCommandAction("curl -i https://x.com/users/1/delete").destructive,
    ).toBe(false);
  });

  it("still flags real host power-state commands", () => {
    expect(classifyCommandAction("sudo reboot").destructive).toBe(true);
    expect(classifyCommandAction("shutdown -h now").destructive).toBe(true);
    expect(classifyCommandAction("echo hi && poweroff").destructive).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Hardening (round 3): obfuscation bypasses + false-positive fixes
// ---------------------------------------------------------------------------

describe("classifier hardening", () => {
  it("flags comment-obfuscated destructive SQL via a DB client", () => {
    expect(
      classifyCommandAction('psql -c "DROP/**/TABLE users"').category,
    ).toBe("sql-destructive");
    expect(
      classifyCommandAction('mysql -e "DELETE/**/FROM sessions"').destructive,
    ).toBe(true);
  });

  it("flags percent-encoded destructive SQL in DB-client args", () => {
    expect(
      classifyCommandAction('psql -c "DROP%20TABLE%20audit"').destructive,
    ).toBe(true);
  });

  it("flags destructive SQL sent through curl/wget (not just http_request)", () => {
    expect(
      classifyCommandAction(
        'curl -X POST -d "q=1;DROP TABLE users--" https://x.com/api',
      ).category,
    ).toBe("sql-destructive");
  });

  it("flags httpie and wget writes to a delete route", () => {
    expect(
      classifyCommandAction("http POST https://x.com/users/1/delete")
        .destructive,
    ).toBe(true);
    expect(
      classifyCommandAction(
        "wget --post-data='x=1' https://x.com/account/destroy",
      ).category,
    ).toBe("http-destructive-path");
  });

  it("normalizes rm path tricks and ~user home wipes", () => {
    expect(classifyCommandAction("rm -rf /tmp/../").destructive).toBe(true);
    expect(classifyCommandAction("rm -rf //").destructive).toBe(true);
    expect(
      classifyCommandAction("rm -rf /home/ubuntu/../../").destructive,
    ).toBe(true);
    expect(classifyCommandAction("rm -rf /*").destructive).toBe(true);
    expect(classifyCommandAction("rm -rf ~alice").destructive).toBe(true);
    // A genuinely-scoped scratch path stays allowed.
    expect(
      classifyCommandAction("rm -rf /tmp/build/../cache").destructive,
    ).toBe(false);
  });

  it("flags dd/redirect wipes of virtual disks but allows pseudo-devices", () => {
    expect(
      classifyCommandAction("dd if=/dev/zero of=/dev/vda").destructive,
    ).toBe(true);
    expect(classifyCommandAction("cat img > /dev/xvda").category).toBe(
      "host-destructive",
    );
    // Discarding output to a pseudo-device is safe.
    expect(
      classifyCommandAction("dd if=/dev/urandom of=/dev/null bs=1M count=1")
        .destructive,
    ).toBe(false);
  });

  it("sees host-destructive commands wrapped in bash -c / sh -lc", () => {
    expect(
      classifyCommandAction('bash -c "dd if=/dev/zero of=/dev/sda"')
        .destructive,
    ).toBe(true);
    expect(
      classifyCommandAction("sh -lc 'mkfs.ext4 /dev/sdb1'").destructive,
    ).toBe(true);
    expect(classifyCommandAction('bash -c "reboot"').destructive).toBe(true);
  });

  it("does not flag DELETE keywords in recon with no HTTP client", () => {
    expect(
      classifyCommandAction('grep -rn "_method=DELETE" src/').destructive,
    ).toBe(false);
    expect(
      classifyCommandAction('echo "pass the -X DELETE flag to remove"')
        .destructive,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Regression: in-script HTTP DELETE nested inside execute_command
// (the Lilt multipart-delete vector — a fetch/axios/Playwright DELETE run via a
// JS runtime, which curl-based and http_request-level controls both miss).
// ---------------------------------------------------------------------------

describe("in-script HTTP DELETE inside execute_command", () => {
  // Encoding 1 — sanitized curl equivalent.
  it("flags a curl DELETE to the multipart path", () => {
    expect(
      classifyCommandAction(
        'curl -i -X DELETE -H "Cookie: session=x" "https://mock-target.test/app/api/upload/s3/multipart/undefined"',
      ).category,
    ).toBe("http-delete-method");
  });

  // Encoding 2 — literal fetch with method: 'DELETE'.
  it("flags a fetch() call with method DELETE", () => {
    expect(
      classifyCommandAction(
        "fetch('/app/api/upload/s3/multipart/undefined', { method: 'DELETE' });",
      ).category,
    ).toBe("http-delete-method");
  });

  // Encoding 3 — dynamically-built path (the closest reproduction: the path is
  // interpolated, so it never contains a literal delete keyword or "undefined").
  it("flags a fetch() DELETE whose path is built dynamically", () => {
    expect(
      classifyCommandAction(
        "node -e \"const id = resp.id; fetch(`/app/api/upload/s3/multipart/${id}`, { method: 'DELETE' })\"",
      ).destructive,
    ).toBe(true);
  });

  it("flags valid-ID DELETE variants and parallel bursts", () => {
    expect(
      classifyCommandAction(
        "node -e \"fetch('/app/api/upload/s3/multipart/81029', { method: 'DELETE' })\"",
      ).destructive,
    ).toBe(true);
    expect(
      classifyCommandAction(
        "node -e \"await Promise.all(Array.from({length:10}, () => fetch('/app/api/upload/s3/multipart/undefined', { method: 'DELETE' })))\"",
      ).destructive,
    ).toBe(true);
  });

  it("flags positional client DELETE calls (axios / Playwright)", () => {
    expect(
      classifyCommandAction("node -e \"axios.delete('/api/x/1')\"").destructive,
    ).toBe(true);
    expect(
      classifyCommandAction(
        "npx playwright test -c \"await page.request.delete('/app/api/upload/s3/multipart/81067')\"",
      ).destructive,
    ).toBe(true);
  });

  it("does not flag benign look-alikes (recon greps, Map.delete, GET fetch)", () => {
    // Grepping source for the literal string is recon, not an HTTP call.
    expect(
      classifyCommandAction("grep -rn \"method: 'DELETE'\" src/").destructive,
    ).toBe(false);
    // Map/Set/Cache .delete() is not an HTTP client.
    expect(
      classifyCommandAction("node -e \"seen.delete('key')\"").destructive,
    ).toBe(false);
    // A non-destructive fetch (GET) stays allowed.
    expect(
      classifyCommandAction("node -e \"fetch('/app/api/upload/s3/multipart')\"")
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

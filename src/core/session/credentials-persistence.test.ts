// Contract tests for WI-1: raw authentication credentials must never enter the
// persisted session.json. Verifies the runtime → persisted conversion, the
// in-memory credential retention on create(), and the legacy-session migration
// that hydrates CredentialManager and strips credentials on the next write.

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CredentialManager } from "../credentials";
import {
  create,
  get,
  sessions,
  toPersistedSession,
  updateOperatorSettings,
} from "./index";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(path.join(tmpdir(), "session-cred-test-"));
  process.env.PENSAR_DATA_DIR = tmpDir;
});

afterEach(() => {
  delete process.env.PENSAR_DATA_DIR;
  rmSync(tmpDir, { recursive: true, force: true });
});

/** Read the raw on-disk session.json for a session id. */
function readPersisted(id: string): Record<string, unknown> {
  const file = path.join(tmpDir, "sessions", id, "session.json");
  return JSON.parse(readFileSync(file, "utf-8"));
}

const CREDS = {
  username: "admin",
  password: "s3cret-password",
  apiKey: "sk-test-key-123",
  loginUrl: "https://example.com/login",
  tokens: { bearerToken: "bearer-abc", cookies: "session=xyz" },
};

/** Assert the runtime session has a live CredentialManager and return it. */
function expectManager(session: {
  credentialManager?: unknown;
}): CredentialManager {
  const cm = session.credentialManager;
  if (!cm || typeof (cm as { resolve?: unknown }).resolve !== "function") {
    throw new Error("expected a live CredentialManager on the session");
  }
  return cm as CredentialManager;
}

// ---------------------------------------------------------------------------
// toPersistedSession
// ---------------------------------------------------------------------------

describe("toPersistedSession", () => {
  it("strips runtime-only fields and config.authCredentials", async () => {
    const session = await create({
      targets: ["https://example.com"],
      config: { authCredentials: CREDS },
    });

    const persisted = toPersistedSession(session);

    expect("_rateLimiter" in persisted).toBe(false);
    expect("credentialManager" in persisted).toBe(false);
    expect(persisted.config).toBeDefined();
    expect("authCredentials" in (persisted.config as object)).toBe(false);
  });

  it("keeps tokensIn/tokensOut (deliberately persisted for benchmark tooling)", async () => {
    const session = await create({ targets: ["https://example.com"] });
    session.tokensIn = 123;
    session.tokensOut = 456;

    const persisted = toPersistedSession(session);

    expect(persisted.tokensIn).toBe(123);
    expect(persisted.tokensOut).toBe(456);
  });

  it("does not mutate the runtime session", async () => {
    const session = await create({
      targets: ["https://example.com"],
      config: { authCredentials: CREDS },
    });

    toPersistedSession(session);

    // Runtime object still has its live credentialManager and config creds.
    expect(session.credentialManager).toBeDefined();
    expect(session.config?.authCredentials).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// create(): secrets absent from disk, retained in memory
// ---------------------------------------------------------------------------

describe("create() — credential persistence", () => {
  it("omits authCredentials and credentialManager from session.json", async () => {
    const session = await create({
      targets: ["https://example.com"],
      config: { authCredentials: CREDS },
    });

    const persisted = readPersisted(session.id);
    const persistedConfig = persisted.config as Record<string, unknown>;

    expect("authCredentials" in persistedConfig).toBe(false);
    expect("credentialManager" in persisted).toBe(false);
    expect("_rateLimiter" in persisted).toBe(false);

    // No secret values anywhere in the serialized file.
    const serialized = JSON.stringify(persisted);
    for (const secret of [
      CREDS.password,
      CREDS.apiKey,
      CREDS.tokens.bearerToken,
      CREDS.tokens.cookies,
    ]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("retains a working in-memory CredentialManager for new sessions", async () => {
    const session = await create({
      targets: ["https://example.com"],
      config: { authCredentials: CREDS },
    });

    const cm = expectManager(session);
    const ids = cm.listReferences();
    expect(ids.length).toBeGreaterThan(0);

    const resolved = cm.resolve(ids[0].id);
    expect(resolved?.username).toBe("admin");
    expect(resolved?.password).toBe(CREDS.password);
    expect(resolved?.apiKey).toBe(CREDS.apiKey);
  });

  it("handles an array of auth credentials", async () => {
    const session = await create({
      targets: ["https://example.com"],
      config: {
        authCredentials: [
          { username: "admin", password: "pw1" },
          { apiKey: "key-2" },
        ],
      },
    });

    expect(expectManager(session).size).toBe(2);
    const persisted = readPersisted(session.id);
    expect("authCredentials" in (persisted.config as object)).toBe(false);
    expect(JSON.stringify(persisted)).not.toContain("pw1");
    expect(JSON.stringify(persisted)).not.toContain("key-2");
  });
});

// ---------------------------------------------------------------------------
// Legacy migration: hydrate in memory, strip on next write
// ---------------------------------------------------------------------------

describe("legacy session migration", () => {
  it("hydrates CredentialManager deterministically from on-disk credentials", async () => {
    // Create a session, then plant legacy credentials directly on disk.
    const session = await create({ targets: ["https://example.com"] });
    const persisted = readPersisted(session.id);
    (persisted.config as Record<string, unknown>).authCredentials = CREDS;
    const file = path.join(tmpDir, "sessions", session.id, "session.json");
    const { writeFileSync } = await import("node:fs");
    writeFileSync(file, JSON.stringify(persisted, null, 2));

    const loaded = await get(session.id);

    // In-memory manager is hydrated from the legacy creds.
    const cm = expectManager(loaded);
    const refs = cm.listReferences();
    expect(refs.length).toBeGreaterThan(0);
    const resolved = cm.resolve(refs[0].id);
    expect(resolved?.username).toBe("admin");
    expect(resolved?.password).toBe(CREDS.password);

    // The in-memory read still sees the legacy config field (runtime path).
    expect(loaded.config?.authCredentials).toBeDefined();
  });

  it("strips credentials from session.json on the next write", async () => {
    // Plant a legacy session with credentials on disk.
    const session = await create({ targets: ["https://example.com"] });
    const file = path.join(tmpDir, "sessions", session.id, "session.json");
    const persisted = readPersisted(session.id);
    (persisted.config as Record<string, unknown>).authCredentials = CREDS;
    const { writeFileSync } = await import("node:fs");
    writeFileSync(file, JSON.stringify(persisted, null, 2));

    // Sanity: credentials are on disk before the write.
    expect(JSON.stringify(readPersisted(session.id))).toContain(CREDS.password);

    // Any update triggers a rewrite that strips runtime-only fields.
    await updateOperatorSettings(session.id, { requireApproval: false });

    const rewritten = readPersisted(session.id);
    expect("authCredentials" in (rewritten.config as object)).toBe(false);
    expect(JSON.stringify(rewritten)).not.toContain(CREDS.password);
    expect(JSON.stringify(rewritten)).not.toContain(CREDS.apiKey);
  });

  it("discards a stale serialized credentialManager plain object on read", async () => {
    const session = await create({ targets: ["https://example.com"] });
    const file = path.join(tmpDir, "sessions", session.id, "session.json");
    const persisted = readPersisted(session.id);
    // Legacy file: raw creds present AND a stale serialized manager object.
    (persisted.config as Record<string, unknown>).authCredentials = CREDS;
    persisted.credentialManager = { store: {} };
    const { writeFileSync } = await import("node:fs");
    writeFileSync(file, JSON.stringify(persisted, null, 2));

    const loaded = await get(session.id);

    // Rehydrated from authCredentials into a real manager, not the stale
    // plain object left on disk.
    const cm = expectManager(loaded);
    const refs = cm.listReferences();
    expect(refs.length).toBeGreaterThan(0);
    expect(cm.resolve(refs[0].id)?.password).toBe(CREDS.password);
  });
});

// ---------------------------------------------------------------------------
// Sessions without credentials remain unaffected
// ---------------------------------------------------------------------------

describe("sessions without credentials", () => {
  it("persists and reloads cleanly with no credential fields", async () => {
    const session = await create({ targets: ["https://example.com"] });

    const persisted = readPersisted(session.id);
    expect("credentialManager" in persisted).toBe(false);
    expect("authCredentials" in (persisted.config as object)).toBe(false);

    const loaded = await get(session.id);
    expect(loaded.credentialManager).toBeUndefined();
    expect(loaded.targets).toEqual(["https://example.com"]);
  });

  it("exposes toPersistedSession on the public sessions namespace via module", () => {
    // sessions namespace re-exports create/get/etc.; toPersistedSession is a
    // direct module export used by the create() write path.
    expect(typeof toPersistedSession).toBe("function");
    expect(typeof sessions.create).toBe("function");
  });
});

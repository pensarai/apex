import { describe, expect, it, vi } from "vitest";
import type {
  AuthCredentialStore,
  CredentialBackend,
  StoredRefreshToken,
} from "./credential-store";
import { CredentialStoreUnavailableError } from "./credential-store";
import {
  AuthRefreshError,
  AuthSessionExpiredError,
  WorkOSTokenManager,
} from "./token";

function futureJwt(subject: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString(
    "base64url",
  );
  const payload = Buffer.from(
    JSON.stringify({ subject, exp: Math.floor(Date.now() / 1000) + 3600 }),
  ).toString("base64url");
  return `${header}.${payload}.signature`;
}

function memoryStore(initial?: string): AuthCredentialStore & {
  current(): string | null;
} {
  let refreshToken = initial ?? null;
  return {
    clear: vi.fn(async () => {
      refreshToken = null;
    }),
    current: () => refreshToken,
    load: vi.fn(
      async (): Promise<StoredRefreshToken | null> =>
        refreshToken ? { backend: "os-vault", refreshToken } : null,
    ),
    save: vi.fn(async (next): Promise<CredentialBackend> => {
      refreshToken = next;
      return "os-vault";
    }),
  };
}

function refreshedResponse(
  accessToken: string,
  refreshToken: string,
): Response {
  return Response.json({
    access_token: accessToken,
    refresh_token: refreshToken,
  });
}

function createManager(options: {
  fetch?: typeof fetch;
  initialRefreshToken?: string;
}) {
  const store = memoryStore(options.initialRefreshToken);
  const updates: Record<string, unknown>[] = [];
  const manager = new WorkOSTokenManager({
    fetch: options.fetch,
    getClientId: async () => "client-id",
    store,
    updateConfig: async (next) => {
      updates.push(next);
    },
    withRefreshLock: async (action) => action(),
  });
  return { manager, store, updates };
}

describe("WorkOSTokenManager", () => {
  it("stores only the refresh token and keeps the access token in memory", async () => {
    const { manager, store, updates } = createManager({});
    const accessToken = futureJwt("saved");

    await manager.saveSession({ accessToken, refreshToken: "refresh-1" });

    expect(store.current()).toBe("refresh-1");
    expect(updates).toEqual([
      {
        accessToken: null,
        credentialBackend: "os-vault",
        refreshToken: null,
        workosSession: true,
      },
    ]);
    await expect(
      manager.ensureValidToken({ workosSession: true }),
    ).resolves.toEqual({ token: accessToken, type: "workos" });
  });

  it("single-flights concurrent refreshes and persists the rotated token first", async () => {
    const accessToken = futureJwt("rotated");
    const fetchMock = vi.fn(async () =>
      refreshedResponse(accessToken, "refresh-2"),
    );
    const { manager, store, updates } = createManager({
      fetch: fetchMock as unknown as typeof fetch,
      initialRefreshToken: "refresh-1",
    });

    const results = await Promise.all([
      manager.ensureValidToken({ workosSession: true }),
      manager.ensureValidToken({ workosSession: true }),
    ]);

    expect(results).toEqual([
      { token: accessToken, type: "workos" },
      { token: accessToken, type: "workos" },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(store.current()).toBe("refresh-2");
    expect(updates.at(-1)).toMatchObject({
      credentialBackend: "os-vault",
      workosSession: true,
    });
  });

  it("force refreshes a token rejected by the API exactly once", async () => {
    const initialAccessToken = futureJwt("initial");
    const refreshedAccessToken = futureJwt("refreshed");
    const fetchMock = vi.fn(async () =>
      refreshedResponse(refreshedAccessToken, "refresh-2"),
    );
    const { manager } = createManager({
      fetch: fetchMock as unknown as typeof fetch,
      initialRefreshToken: "refresh-1",
    });
    await manager.saveSession({
      accessToken: initialAccessToken,
      refreshToken: "refresh-1",
    });

    await expect(
      manager.ensureValidToken(
        { workosSession: true },
        { forceRefresh: true, rejectedToken: initialAccessToken },
      ),
    ).resolves.toEqual({ token: refreshedAccessToken, type: "workos" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the refresh token after a transient refresh failure", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("offline");
    });
    const { manager, store } = createManager({
      fetch: fetchMock as unknown as typeof fetch,
      initialRefreshToken: "refresh-1",
    });

    await expect(
      manager.ensureValidToken({ workosSession: true }),
    ).rejects.toBeInstanceOf(AuthRefreshError);
    expect(store.current()).toBe("refresh-1");
  });

  it("preserves the session marker when the credential store is locked", async () => {
    const updates: Record<string, unknown>[] = [];
    const manager = new WorkOSTokenManager({
      getClientId: async () => "client-id",
      store: {
        clear: async () => {},
        load: async () => {
          throw new CredentialStoreUnavailableError();
        },
        save: async () => "os-vault",
      },
      updateConfig: async (next) => {
        updates.push(next);
      },
      withRefreshLock: async (action) => action(),
    });

    await expect(
      manager.ensureValidToken({ workosSession: true }),
    ).rejects.toBeInstanceOf(AuthRefreshError);
    expect(updates).toEqual([]);
  });

  it("clears an invalid refresh session", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 401 }));
    const { manager, store, updates } = createManager({
      fetch: fetchMock as unknown as typeof fetch,
      initialRefreshToken: "invalid-refresh",
    });

    await expect(
      manager.ensureValidToken({ workosSession: true }),
    ).rejects.toBeInstanceOf(AuthSessionExpiredError);
    expect(store.current()).toBeNull();
    expect(updates.at(-1)).toEqual({
      accessToken: null,
      credentialBackend: null,
      refreshToken: null,
      workosSession: false,
    });
  });

  it("migrates legacy plaintext tokens into secure storage", async () => {
    const { manager, store, updates } = createManager({});
    const accessToken = futureJwt("legacy");

    await expect(
      manager.ensureValidToken({
        accessToken,
        refreshToken: "legacy-refresh",
      }),
    ).resolves.toEqual({ token: accessToken, type: "workos" });

    expect(store.current()).toBe("legacy-refresh");
    expect(updates).toContainEqual({
      accessToken: null,
      credentialBackend: "os-vault",
      refreshToken: null,
      workosSession: true,
    });
  });

  it("clears a stale session marker when its credential is gone", async () => {
    const { manager, updates } = createManager({});

    await expect(
      manager.ensureValidToken({ workosSession: true }),
    ).rejects.toBeInstanceOf(AuthSessionExpiredError);
    expect(updates).toContainEqual({
      credentialBackend: null,
      workosSession: false,
    });
  });
});

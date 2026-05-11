import { mkdtempSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from "vitest";
import { CredentialManager } from "../../../credentials";
import type { SessionInfo } from "../../../session";
import {
  authenticateSession,
  extractAuthArtifacts,
  extractBearerToken,
  extractRefreshToken,
} from "./authenticateSession";
import type { ToolContext } from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCtx(overrides: Partial<ToolContext> = {}): {
  ctx: ToolContext;
  rootPath: string;
} {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-auth-test-"));
  const ctx: ToolContext = {
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath,
      logsPath: join(rootPath, "logs"),
      findingsPath: join(rootPath, "findings"),
      scratchpadPath: join(rootPath, "scratchpad"),
      pocsPath: join(rootPath, "pocs"),
    } as SessionInfo,
    agentCwd: rootPath,
    ...overrides,
  };
  return { ctx, rootPath };
}

interface ResponseInit {
  status: number;
  body?: string;
  contentType?: string;
  setCookie?: string[];
}

function mockResponse({
  status,
  body = "",
  contentType,
  setCookie,
}: ResponseInit): Response {
  const headers = new Headers();
  if (contentType) headers.set("content-type", contentType);
  if (setCookie) {
    for (const c of setCookie) headers.append("set-cookie", c);
  }
  return new Response(body, { status, headers });
}

function readSessionInfo(rootPath: string) {
  const raw = readFileSync(join(rootPath, "session-info.json"), "utf-8");
  return JSON.parse(raw);
}

// ---------------------------------------------------------------------------
// extractBearerToken / extractRefreshToken
// ---------------------------------------------------------------------------

describe("extractBearerToken", () => {
  it("finds access_token", () => {
    expect(extractBearerToken({ access_token: "abc123" })).toBe("abc123");
  });

  it("finds accessToken (camelCase)", () => {
    expect(extractBearerToken({ accessToken: "abc" })).toBe("abc");
  });

  it("prefers access_token over generic token", () => {
    expect(extractBearerToken({ token: "csrf", access_token: "jwt" })).toBe(
      "jwt",
    );
  });

  it("falls through to id_token / jwt / token in priority order", () => {
    expect(extractBearerToken({ id_token: "id", token: "t" })).toBe("id");
    expect(extractBearerToken({ jwt: "j", token: "t" })).toBe("j");
    expect(extractBearerToken({ token: "only" })).toBe("only");
  });

  it("returns empty for missing or non-string fields", () => {
    expect(extractBearerToken({})).toBe("");
    expect(extractBearerToken({ access_token: 123 })).toBe("");
    expect(extractBearerToken(null)).toBe("");
    expect(extractBearerToken("string-not-object")).toBe("");
  });

  it("unwraps one level of nesting under data / result / auth / session", () => {
    expect(extractBearerToken({ data: { access_token: "abc" } })).toBe("abc");
    expect(extractBearerToken({ result: { jwt: "j" } })).toBe("j");
    expect(extractBearerToken({ auth: { token: "t" } })).toBe("t");
  });
});

describe("extractRefreshToken", () => {
  it("finds refresh_token and refreshToken", () => {
    expect(extractRefreshToken({ refresh_token: "r" })).toBe("r");
    expect(extractRefreshToken({ refreshToken: "r2" })).toBe("r2");
  });

  it("returns empty when absent", () => {
    expect(extractRefreshToken({ access_token: "a" })).toBe("");
  });
});

// ---------------------------------------------------------------------------
// extractAuthArtifacts
// ---------------------------------------------------------------------------

describe("extractAuthArtifacts", () => {
  it("returns cookies from Set-Cookie", async () => {
    const res = mockResponse({
      status: 200,
      setCookie: ["session=abc; Path=/", "csrf=xyz"],
    });
    const out = await extractAuthArtifacts(res);
    expect(out.sessionCookie).toContain("session=abc");
    expect(out.sessionCookie).toContain("csrf=xyz");
    expect(out.bearerToken).toBe("");
  });

  it("returns bearer token from JSON body", async () => {
    const res = mockResponse({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ access_token: "jwt-here", refresh_token: "r" }),
    });
    const out = await extractAuthArtifacts(res);
    expect(out.bearerToken).toBe("jwt-here");
    expect(out.refreshToken).toBe("r");
  });

  it("returns both cookies and bearer when both are present", async () => {
    const res = mockResponse({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ access_token: "jwt-here" }),
      setCookie: ["session=abc"],
    });
    const out = await extractAuthArtifacts(res);
    expect(out.bearerToken).toBe("jwt-here");
    expect(out.sessionCookie).toContain("session=abc");
  });

  it("preserves body preview (truncated when long)", async () => {
    const longBody = "x".repeat(2000);
    const res = mockResponse({
      status: 422,
      contentType: "application/json",
      body: longBody,
    });
    const out = await extractAuthArtifacts(res);
    expect(out.bodyPreview.length).toBeLessThan(longBody.length);
    expect(out.bodyPreview.endsWith("…")).toBe(true);
  });

  it("ignores invalid JSON without throwing", async () => {
    const res = mockResponse({
      status: 200,
      contentType: "application/json",
      body: "not-json",
    });
    const out = await extractAuthArtifacts(res);
    expect(out.bearerToken).toBe("");
    expect(out.bodyPreview).toBe("not-json");
  });
});

// ---------------------------------------------------------------------------
// authenticate_session tool — end-to-end via mocked fetch
// ---------------------------------------------------------------------------

describe("authenticate_session tool", () => {
  let fetchSpy: MockInstance<typeof fetch> | undefined;
  let rootPath: string | undefined;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    fetchSpy?.mockRestore();
    if (rootPath) {
      try {
        rmSync(rootPath, { recursive: true, force: true });
      } catch {
        // best effort
      }
      rootPath = undefined;
    }
  });

  // `tool.execute` is typed as returning a value OR an AsyncIterable; the
  // implementation never streams, so narrow to the value branch for tests.
  type AuthToolResult = Exclude<
    Awaited<
      ReturnType<NonNullable<ReturnType<typeof authenticateSession>["execute"]>>
    >,
    AsyncIterable<unknown>
  >;

  async function callTool(
    params: Record<string, unknown>,
  ): Promise<{ result: AuthToolResult; rootPath: string }> {
    const setup = makeCtx();
    rootPath = setup.rootPath;
    const tool = authenticateSession(setup.ctx);
    // The execute signature is (params, callContext) — we don't need the
    // call context for these tests, so we pass a minimal stub.
    return {
      result: (await tool.execute!(
        {
          method: "form_post",
          usernameField: "username",
          passwordField: "password",
          toolCallDescription: "test",
          ...params,
        },
        { toolCallId: "", messages: [], abortSignal: undefined as never },
      )) as AuthToolResult,
      rootPath: setup.rootPath,
    };
  }

  it("marks JWT JSON responses as authenticated (OAuth2-style token endpoint)", async () => {
    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          user_id: "u1",
          access_token: "JWT-VALUE",
          refresh_token: "R-VALUE",
        }),
      }),
    );

    const { result, rootPath } = await callTool({
      loginUrl: "https://auth.example.com/signin",
      username: "alice",
      password: "secret",
      method: "form_post",
    });

    expect(result).toMatchObject({
      success: true,
      authenticated: true,
      statusCode: 200,
      bearerToken: "JWT-VALUE",
      refreshToken: "R-VALUE",
      authorizationHeader: "Bearer JWT-VALUE",
    });

    const persisted = readSessionInfo(rootPath);
    expect(persisted.authenticated).toBe(true);
    expect(persisted.bearerToken).toBe("JWT-VALUE");
    expect(persisted.authorizationHeader).toBe("Bearer JWT-VALUE");

    // form-encoded body and correct Content-Type
    const init = fetchSpy!.mock.calls[0]![1] as RequestInit;
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/x-www-form-urlencoded",
    );
    expect(String(init.body)).toContain("username=alice");
    expect(String(init.body)).toContain("password=secret");
  });

  it("marks cookie-only responses as authenticated", async () => {
    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 200,
        setCookie: ["session=abc; HttpOnly; Path=/"],
      }),
    );

    const { result } = await callTool({
      loginUrl: "https://example.com/login",
      username: "alice",
      password: "secret",
    });

    expect(result).toMatchObject({
      success: true,
      authenticated: true,
      bearerToken: "",
    });
    expect(result.sessionCookie).toContain("session=abc");
  });

  it("fails when 2xx returns no Set-Cookie and no recognizable token", async () => {
    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true }),
      }),
    );

    const { result } = await callTool({
      loginUrl: "https://example.com/login",
      username: "alice",
      password: "secret",
    });

    expect(result.success).toBe(false);
    expect(result.authenticated).toBe(false);
    expect(result.message).toMatch(/no Set-Cookie or recognizable bearer/i);
  });

  it("returns a 405-specific hint and response body on Method Not Allowed", async () => {
    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 405,
        contentType: "text/html",
        body: "<html><body>Method not allowed</body></html>",
      }),
    );

    const { result } = await callTool({
      loginUrl: "https://example.com/sign-in",
      username: "alice",
      password: "secret",
    });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(405);
    expect(result.message).toMatch(/page route/i);
    expect(result.responseBody).toContain("Method not allowed");
  });

  it("returns a 422-specific hint on Unprocessable Entity", async () => {
    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 422,
        contentType: "application/json",
        body: JSON.stringify({ detail: "username field required" }),
      }),
    );

    const { result } = await callTool({
      loginUrl: "https://example.com/api/login",
      username: "alice",
      password: "secret",
      method: "json_post",
    });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(422);
    expect(result.message).toMatch(/Content-Type|field names/);
    expect(result.responseBody).toContain("username field required");
  });

  it("returns a 401-specific hint and tells the agent to stop", async () => {
    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: "Invalid login credentials" }),
      }),
    );

    const { result } = await callTool({
      loginUrl: "https://example.com/signin",
      username: "alice",
      password: "wrong",
    });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
    expect(result.message).toMatch(/do not retry|credentials are wrong/i);
  });

  it("resolves credentials and loginUrl from a credentialId", async () => {
    const cm = new CredentialManager();
    const credId = cm.add({
      username: "bob",
      password: "p4ss",
      loginUrl: "https://example.com/api/login",
    });

    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ access_token: "T" }),
      }),
    );

    const setup = makeCtx({ credentialManager: cm });
    rootPath = setup.rootPath;
    const tool = authenticateSession(setup.ctx);
    const result = (await tool.execute!(
      {
        credentialId: credId,
        method: "form_post",
        usernameField: "username",
        passwordField: "password",
        toolCallDescription: "test",
      },
      { toolCallId: "", messages: [], abortSignal: undefined as never },
    )) as AuthToolResult;

    expect(result.authenticated).toBe(true);
    expect(result.bearerToken).toBe("T");
    // Verify it actually hit the credential's loginUrl
    expect(fetchSpy!.mock.calls[0]![0]).toBe("https://example.com/api/login");
  });

  it("scrubs bearer token from responseBody on successful JWT auth", async () => {
    fetchSpy!.mockResolvedValue(
      mockResponse({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ access_token: "JWT-LONG-ENOUGH-TO-SCRUB" }),
      }),
    );

    const { result } = await callTool({
      loginUrl: "https://example.com/signin",
      username: "alice",
      password: "secret",
    });

    expect(result.authenticated).toBe(true);
    expect(result.bearerToken).toBe("JWT-LONG-ENOUGH-TO-SCRUB");
    expect(result.responseBody).not.toContain("JWT-LONG-ENOUGH-TO-SCRUB");
    expect(result.responseBody).toContain("<redacted>");
  });
});

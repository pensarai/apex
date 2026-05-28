import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createBrowserTools,
  PlaywrightMcpSession,
  parseStorageStateResult,
  setViewportSize,
  transformScriptToFunction,
} from "./playwrightMcp";

describe("transformScriptToFunction", () => {
  describe("plain expressions", () => {
    it("wraps simple expression in arrow function", () => {
      expect(transformScriptToFunction("document.cookie")).toBe(
        "() => (document.cookie)",
      );
    });

    it("wraps complex expression", () => {
      expect(transformScriptToFunction("localStorage.getItem('token')")).toBe(
        "() => (localStorage.getItem('token'))",
      );
    });

    it("handles expression with whitespace", () => {
      expect(transformScriptToFunction("  document.title  ")).toBe(
        "() => (  document.title  )",
      );
    });
  });

  describe("function expressions", () => {
    it("passes through arrow function", () => {
      const fn = "() => document.cookie";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through arrow function with body", () => {
      const fn = "() => { return document.cookie; }";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through async arrow function", () => {
      const fn = "async () => fetch('/api')";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through function expression", () => {
      const fn = "function() { return document.cookie; }";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("passes through async function expression", () => {
      const fn = "async function() { return await fetch('/api'); }";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("handles arrow function with parameters", () => {
      const fn = "(a, b) => a + b";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });
  });

  describe("IIFEs", () => {
    it("extracts function from simple arrow IIFE", () => {
      const iife = "(() => document.cookie)()";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });

    it("extracts function from arrow IIFE with body", () => {
      const iife = `(() => {
  const tokens = {};
  return tokens;
})()`;
      const expected = `() => {
  const tokens = {};
  return tokens;
}`;
      expect(transformScriptToFunction(iife)).toBe(expected);
    });

    it("extracts function from complex arrow IIFE (from bug report)", () => {
      const iife = `(() => {
  const tokens = {};
  const keys = ['token', 'access_token', 'accessToken', 'auth_token', 'jwt', 'id_token'];
  keys.forEach(key => {
    const lsVal = localStorage.getItem(key);
    const ssVal = sessionStorage.getItem(key);
    if (lsVal) tokens[key + '_localStorage'] = lsVal;
    if (ssVal) tokens[key + '_sessionStorage'] = ssVal;
  });
  return JSON.stringify(tokens, null, 2);
})()
`;
      const result = transformScriptToFunction(iife);
      expect(result).toContain("() => {");
      expect(result).toContain("const tokens = {};");
      expect(result).toContain("return JSON.stringify(tokens, null, 2);");
      expect(result).not.toContain(")()");
    });

    it("extracts function from async arrow IIFE", () => {
      const iife = "(async () => await fetch('/api'))()";
      expect(transformScriptToFunction(iife)).toBe(
        "async () => await fetch('/api')",
      );
    });

    it("extracts function from function IIFE", () => {
      const iife = "(function() { return document.cookie; })()";
      expect(transformScriptToFunction(iife)).toBe(
        "function() { return document.cookie; }",
      );
    });

    it("extracts function from async function IIFE", () => {
      const iife = "(async function() { return await fetch('/api'); })()";
      expect(transformScriptToFunction(iife)).toBe(
        "async function() { return await fetch('/api'); }",
      );
    });

    it("handles IIFE with trailing semicolon", () => {
      const iife = "(() => document.cookie)();";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });

    it("handles IIFE with whitespace in invocation", () => {
      const iife = "(() => document.cookie)(  )";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });

    it("handles IIFE with trailing whitespace", () => {
      const iife = "(() => document.cookie)()   ";
      expect(transformScriptToFunction(iife)).toBe("() => document.cookie");
    });
  });

  describe("edge cases", () => {
    it("handles function that returns a function call", () => {
      const fn = "() => doSomething()";
      expect(transformScriptToFunction(fn)).toBe(fn);
    });

    it("does not mis-identify function call as IIFE", () => {
      const expr = "myFunction()";
      expect(transformScriptToFunction(expr)).toBe("() => (myFunction())");
    });

    it("handles JSON stringify in expression", () => {
      const expr = "JSON.stringify({a: 1})";
      expect(transformScriptToFunction(expr)).toBe(
        "() => (JSON.stringify({a: 1}))",
      );
    });

    it("handles empty parentheses expression", () => {
      const expr = "()";
      expect(transformScriptToFunction(expr)).toBe("()");
    });
  });
});

describe("PlaywrightMcpSession — constructor defaults", () => {
  // Internal field accessor — we don't want to expose getters publicly,
  // but the defaults invariant is important enough to assert directly.
  type InternalShape = {
    headless: boolean;
    userAgent: string | undefined;
    viewportSize: string | undefined;
  };

  it("defaults to headless + desktop UA + 1920x1080 when constructed with no args (regression: don't fall back to Chromium's tiny default viewport)", () => {
    const session = new PlaywrightMcpSession() as unknown as InternalShape;
    expect(session.headless).toBe(true);
    expect(session.viewportSize).toBe("1920,1080");
    expect(session.userAgent).toContain("Chrome/");
  });

  it("uses explicit values when provided", () => {
    const session = new PlaywrightMcpSession({
      headless: false,
      userAgent: "MyAgent/1.0",
      viewportSize: "800,600",
    }) as unknown as InternalShape;
    expect(session.headless).toBe(false);
    expect(session.userAgent).toBe("MyAgent/1.0");
    expect(session.viewportSize).toBe("800,600");
  });

  it("treats explicit null as 'opt out of the default' (let Chromium pick its built-in)", () => {
    const session = new PlaywrightMcpSession({
      headless: true,
      userAgent: null,
      viewportSize: null,
    }) as unknown as InternalShape;
    expect(session.userAgent).toBeUndefined();
    expect(session.viewportSize).toBeUndefined();
  });

  it("falls back to a hardcoded 1920x1080 floor for viewport even if the module default was cleared (regression: don't ship a Chromium-tiny viewport just because someone called setViewportSize(undefined))", () => {
    const original = "1920,1080";
    try {
      setViewportSize(undefined);
      const session = new PlaywrightMcpSession() as unknown as InternalShape;
      expect(session.viewportSize).toBe("1920,1080");
    } finally {
      // Restore the module default for any subsequent test.
      setViewportSize(original);
    }
  });
});

describe("parseStorageStateResult", () => {
  it("returns null for null/undefined input", () => {
    expect(parseStorageStateResult(null)).toBeNull();
    expect(parseStorageStateResult(undefined)).toBeNull();
  });

  it("parses the Playwright-MCP wrapped string format", () => {
    const wrapped = `### Result\n{"cookies":[{"name":"a","value":"b","domain":"x","path":"/"}],"origins":[]}\n\n### Ran Playwright code\nfoo`;
    const out = parseStorageStateResult(wrapped);
    expect(out).not.toBeNull();
    expect(out!.cookies[0].name).toBe("a");
    expect(out!.origins).toEqual([]);
  });

  it("falls back to a regex JSON extract for unwrapped strings", () => {
    const raw = `garbage prefix {"cookies":[],"origins":[{"origin":"https://x","localStorage":[]}]} trailing`;
    const out = parseStorageStateResult(raw);
    expect(out).not.toBeNull();
    expect(out!.origins[0].origin).toBe("https://x");
  });

  it("accepts a pre-parsed object directly", () => {
    const obj = { cookies: [], origins: [] };
    expect(parseStorageStateResult(obj)).toEqual(obj);
  });

  it("rejects objects without a cookies field", () => {
    expect(parseStorageStateResult({ foo: 1 })).toBeNull();
  });

  it("rejects strings that are not valid JSON storageState payloads", () => {
    expect(parseStorageStateResult("totally not json")).toBeNull();
  });
});

describe("createBrowserTools — shared session reuse", () => {
  let evidenceDir: string;

  beforeEach(() => {
    evidenceDir = mkdtempSync(join(tmpdir(), "apex-pw-test-"));
  });

  afterEach(() => {
    rmSync(evidenceDir, { recursive: true, force: true });
  });

  it("reuses an existing PlaywrightMcpSession when one is provided", async () => {
    const sharedSession = new PlaywrightMcpSession();
    const callTool = vi
      .spyOn(sharedSession, "callTool")
      // biome-ignore lint/suspicious/noExplicitAny: stubbing a private MCP transport for the test.
      .mockResolvedValue({ ok: true } as any);

    const tools = createBrowserTools(
      "https://example.com",
      evidenceDir,
      "operator",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      sharedSession,
    );

    // Invoke a browser tool; it should call through to the SHARED session.
    await tools.browser_navigate.execute!(
      { url: "https://example.com/login", toolCallDescription: "test" },
      // biome-ignore lint/suspicious/noExplicitAny: ai-sdk ToolCallOptions is opaque and irrelevant for this test.
      { toolCallId: "tc1", messages: [], abortSignal: undefined } as any,
    );

    expect(callTool).toHaveBeenCalledTimes(1);
    expect(callTool).toHaveBeenCalledWith(
      "browser_navigate",
      { url: "https://example.com/login" },
      undefined,
    );
  });

  it("captureStorageState returns null when the session has never connected", async () => {
    const session = new PlaywrightMcpSession();
    expect(session.isConnected()).toBe(false);
    const state = await session.captureStorageState();
    expect(state).toBeNull();
  });

  it("captureStorageState parses a Playwright-MCP wrapped storageState response", async () => {
    const session = new PlaywrightMcpSession();
    vi.spyOn(session, "isConnected").mockReturnValue(true);

    const wrapped = `### Result\n${JSON.stringify({
      cookies: [
        {
          name: "session",
          value: "abc123",
          domain: "example.com",
          path: "/",
          httpOnly: true,
          secure: true,
          sameSite: "Lax" as const,
        },
      ],
      origins: [
        {
          origin: "https://example.com",
          localStorage: [{ name: "uid", value: "alice" }],
        },
      ],
    })}\n\n### Ran Playwright code\nawait page.context().storageState()`;

    vi.spyOn(session, "callTool").mockResolvedValue(wrapped);

    const state = await session.captureStorageState();
    expect(state).not.toBeNull();
    expect(state!.cookies).toHaveLength(1);
    expect(state!.cookies[0].name).toBe("session");
    expect(state!.origins).toHaveLength(1);
    expect(state!.origins[0].localStorage[0].value).toBe("alice");
  });

  it("seedStorageState forwards cookies + origins into a browser_run_code call", async () => {
    const session = new PlaywrightMcpSession();
    // Skip the real MCP spawn — seedStorageState calls initialize first.
    vi.spyOn(session, "initialize").mockResolvedValue({} as never);
    const callSpy = vi.spyOn(session, "callTool").mockResolvedValue({});

    const state = {
      cookies: [
        {
          name: "session",
          value: "tok",
          domain: "example.com",
          path: "/",
          httpOnly: false,
          secure: true,
          sameSite: "Lax" as const,
        },
      ],
      origins: [
        {
          origin: "https://example.com",
          localStorage: [{ name: "uid", value: "alice" }],
        },
      ],
    };

    await session.seedStorageState(state);

    expect(callSpy).toHaveBeenCalledTimes(1);
    const [toolName, args] = callSpy.mock.calls[0] as [
      string,
      { code: string },
    ];
    expect(toolName).toBe("browser_run_code");
    // The injected code carries the cookies + localStorage payload verbatim.
    expect(args.code).toContain('"name":"session"');
    expect(args.code).toContain('"uid"');
    expect(args.code).toContain("addCookies");
    expect(args.code).toContain("addInitScript");
  });

  it("does not register an abort handler that would tear down a borrowed session", async () => {
    const sharedSession = new PlaywrightMcpSession();
    const disconnectSpy = vi
      .spyOn(sharedSession, "disconnect")
      .mockResolvedValue(undefined);

    const controller = new AbortController();

    createBrowserTools(
      "https://example.com",
      evidenceDir,
      "operator",
      undefined,
      controller.signal,
      undefined,
      undefined,
      undefined,
      sharedSession,
    );

    // Aborting the SUB-AGENT's signal must NOT disconnect the parent's
    // shared browser session — only the original owner is allowed to
    // tear it down.
    controller.abort();
    // Give the (non-)abort listener a chance to fire.
    await new Promise((r) => setTimeout(r, 5));

    expect(disconnectSpy).not.toHaveBeenCalled();
  });
});

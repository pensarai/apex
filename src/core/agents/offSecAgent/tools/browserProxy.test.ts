import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionInfoObject } from "../../../session";
import { PlaywrightMcpSession } from "./playwrightMcp";
import { createSandboxBrowserToolFactories } from "./sandboxPlaywright";
import type { ToolContext } from "./types";

vi.mock("./camoufox", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./camoufox")>()),
  ensureCamoufox: vi.fn(),
  resolveCamoufoxLaunchOptions: vi.fn(async () => ({
    executablePath: "/test/browser",
    args: [],
    firefoxUserPrefs: {},
    headless: true,
    env: {},
  })),
}));

afterEach(() => vi.restoreAllMocks());

const proxy = {
  server: "http://proxy.example.test:3128",
  username: "test-user",
  password: "test-password",
  bypass: "localhost",
};

function launchConfig(session: PlaywrightMcpSession) {
  return (
    session as unknown as {
      buildMcpLaunch(id: string): Promise<{ cfg: unknown }>;
    }
  ).buildMcpLaunch("test-launch");
}

describe("browser proxy configuration", () => {
  it("preserves proxy settings when session configuration is parsed", () => {
    expect(
      SessionInfoObject.shape.config.parse({ browserProxy: proxy }),
    ).toEqual({ browserProxy: proxy });
    expect(() =>
      SessionInfoObject.shape.config.parse({
        browserProxy: { server: "not a URL" },
      }),
    ).toThrow();
  });

  it.each([
    "chrome",
    "camoufox",
  ] as const)("passes the full proxy configuration to %s launch", async (engine) => {
    const session = new PlaywrightMcpSession({ engine, proxy });
    const launch = await launchConfig(session);
    expect(launch.cfg).toMatchObject({ browser: { launchOptions: { proxy } } });
  });

  it.each([
    "chrome",
    "camoufox",
  ] as const)("does not configure a proxy for %s when omitted", async (engine) => {
    const session = new PlaywrightMcpSession({ engine });
    const launch = await launchConfig(session);
    expect(launch.cfg).toMatchObject({
      browser: {
        launchOptions: expect.not.objectContaining({
          proxy: expect.anything(),
        }),
      },
    });
  });

  it("snapshots caller configuration so later mutations do not change reconnects", async () => {
    const mutable = { ...proxy };
    const session = new PlaywrightMcpSession({
      engine: "chrome",
      proxy: mutable,
    });
    mutable.server = "http://different.example.test:3128";
    expect((await launchConfig(session)).cfg).toMatchObject({
      browser: { launchOptions: { proxy } },
    });
  });

  it("forwards session proxy credentials to remote browser launch without shell interpolation", async () => {
    const remoteProxy = { ...proxy, password: "quotes'`$()\\\"" };
    const scripts: string[] = [];
    const execute = vi.fn(async (command: string) => {
      const encoded = command.match(/echo "([A-Za-z0-9+/=]+)" \| base64 -d/);
      if (encoded)
        scripts.push(Buffer.from(encoded[1], "base64").toString("utf8"));
      return { success: true, stdout: "OK", stderr: "" };
    });
    const ctx = {
      sandbox: { execute },
      session: {
        rootPath: "/tmp/browser-proxy-test",
        config: { browserProxy: remoteProxy },
      },
      target: "https://target.example.test",
    } as unknown as ToolContext;
    const navigate = createSandboxBrowserToolFactories(ctx).browser_navigate();
    await navigate.execute?.(
      { url: "https://target.example.test", toolCallDescription: "open page" },
      { toolCallId: "test", messages: [] },
    );
    const launch = scripts.find((script) =>
      script.includes("launchPersistentContext"),
    );
    expect(launch).toContain(`...${JSON.stringify({ proxy: remoteProxy })}`);
    expect(execute).toHaveBeenCalled();
  });
});

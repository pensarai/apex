import { once } from "node:events";
import { existsSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import {
  browserHeaderRouteFunction,
  resolveBrowserHeaderPolicy,
} from "./browserHeaderRouting";

const CHROME_PATH = "/usr/local/bin/google-chrome";
const requireFromHere = createRequire(import.meta.url);
const servers: Server[] = [];

async function listen(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<number> {
  const server = createServer(handler);
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("redirect fixture did not bind");
  }
  return address.port;
}

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve) => server.close(() => resolve())),
      ),
  );
});

describe.runIf(existsSync(CHROME_PATH))(
  "browser scoped redirect boundary",
  () => {
    it("aborts an allowed-host redirect before the browser reaches an unlisted host", async () => {
      let destinationReached = false;
      let secretReceived = false;
      const destinationPort = await listen((request, response) => {
        destinationReached = true;
        secretReceived = request.headers["x-engagement-secret"] === "secret";
        response.end("outside");
      });
      const initialPort = await listen((_request, response) => {
        response.writeHead(302, {
          location: `http://localhost:${destinationPort}/outside`,
        });
        response.end();
      });

      const mcpEntry = requireFromHere.resolve("@playwright/mcp");
      const playwrightEntry = requireFromHere.resolve("playwright-core", {
        paths: [mcpEntry],
      });
      const playwright = requireFromHere(playwrightEntry) as {
        chromium: {
          launch(options: {
            executablePath: string;
            headless: boolean;
            args: string[];
          }): Promise<{
            close(): Promise<void>;
            newContext(): Promise<{
              close(): Promise<void>;
              newPage(): Promise<{
                goto(
                  url: string,
                  options: { timeout: number; waitUntil: string },
                ): Promise<unknown>;
              }>;
              route(
                pattern: string,
                handler: (route: unknown) => Promise<void>,
              ): Promise<void>;
            }>;
          }>;
        };
      };
      const browser = await playwright.chromium.launch({
        executablePath: CHROME_PATH,
        headless: true,
        args: ["--no-sandbox"],
      });

      try {
        const context = await browser.newContext();
        try {
          const policy = resolveBrowserHeaderPolicy(
            {
              targets: [`http://127.0.0.1:${initialPort}`],
              config: {
                headers: { "X-Engagement-Secret": "secret" },
                scopeConstraints: {
                  allowedHosts: ["127.0.0.1"],
                  allowedPorts: [initialPort],
                  strictScope: true,
                },
              },
            },
            `http://127.0.0.1:${initialPort}`,
          );
          const installRoute = runInNewContext(
            `(${browserHeaderRouteFunction(policy)})`,
            { URL },
          ) as (page: {
            context(): typeof context;
          }) => Promise<{ installed: boolean }>;
          await installRoute({ context: () => context });

          const page = await context.newPage();
          await expect(
            page.goto(`http://127.0.0.1:${initialPort}/start`, {
              timeout: 5_000,
              waitUntil: "domcontentloaded",
            }),
          ).rejects.toThrow();
        } finally {
          await context.close();
        }
      } finally {
        await browser.close();
      }

      expect(destinationReached).toBe(false);
      expect(secretReceived).toBe(false);
    });
  },
);

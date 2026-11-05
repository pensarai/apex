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

const CHROME_PATH =
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ??
  "/usr/local/bin/google-chrome";
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
    it("follows an allowed-host redirect to an unlisted host without sending it engagement headers", async () => {
      let destinationReached = false;
      let secretReceived = false;
      const destinationPort = await listen((request, response) => {
        destinationReached = true;
        secretReceived = request.headers["x-engagement-secret"] === "secret";
        response.end("outside");
      });
      const scopedHeaders: string[] = [];
      const initialPort = await listen((request, response) => {
        if (request.headers["x-engagement-secret"] === "secret") {
          scopedHeaders.push(request.url ?? "");
        }
        if (request.url === "/start") {
          response.writeHead(302, {
            location: `http://localhost:${destinationPort}/outside`,
          });
          response.end();
        } else if (request.url === "/app.js") {
          response.writeHead(200, { "content-type": "application/javascript" });
          response.end('document.body.dataset.loaded = "yes";');
        } else {
          response.writeHead(200, { "content-type": "text/html" });
          response.end(
            '<body><script type="module" src="/app.js"></script></body>',
          );
        }
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
                evaluate(
                  fn: () => string | undefined,
                ): Promise<string | undefined>;
                goto(
                  url: string,
                  options: { timeout: number; waitUntil: string },
                ): Promise<unknown>;
              }>;
              route(
                pattern: string,
                handler: (route: {
                  fallback(): Promise<void>;
                }) => Promise<void>,
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
          let priorFallbackReached = false;
          await context.route("**/*", async (route) => {
            priorFallbackReached = true;
            await route.fallback();
          });
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
            {},
          ) as (page: {
            context(): typeof context;
          }) => Promise<{ installed: boolean }>;
          await installRoute({ context: () => context });
          let newerFallbackReached = false;
          await context.route("**/*", async (route) => {
            newerFallbackReached = true;
            await route.fallback();
          });

          const page = await context.newPage();
          await page.goto(`http://127.0.0.1:${initialPort}/`, {
            timeout: 5_000,
            waitUntil: "networkidle",
          });
          expect(await page.evaluate(() => document.body.dataset.loaded)).toBe(
            "yes",
          );
          expect(scopedHeaders).toEqual(
            expect.arrayContaining(["/", "/app.js"]),
          );
          expect(newerFallbackReached).toBe(true);
          expect(priorFallbackReached).toBe(false);
          await page.goto(`http://127.0.0.1:${initialPort}/start`, {
            timeout: 5_000,
            waitUntil: "domcontentloaded",
          });
        } finally {
          await context.close();
        }
      } finally {
        await browser.close();
      }

      expect(destinationReached).toBe(true);
      expect(secretReceived).toBe(false);
    });
  },
);

/**
 * Direct test of browser cookie extraction via Playwright MCP.
 * Bypasses the LLM agent entirely to verify the browser_get_cookies tool works.
 */
import { PlaywrightMcpSession } from "../core/agents/offSecAgent/tools/playwrightMcp";
import { describe, it, expect, afterEach } from "vitest";
import { config } from "dotenv";

config();

describe("Browser Cookie Extraction", () => {
  let session: PlaywrightMcpSession;

  afterEach(async () => {
    await session?.disconnect();
  });

  it(
    "should extract httpOnly cookies via browser_run_code after authenticating",
    async () => {
      const username = process.env.TEST_AUTH_USERNAME;
      const password = process.env.TEST_AUTH_PASSWORD;
      if (!username || !password) {
        console.warn(
          "Skipping: TEST_AUTH_USERNAME and TEST_AUTH_PASSWORD must be set",
        );
        return;
      }

      session = new PlaywrightMcpSession(true);
      await session.initialize();

      // Navigate to login — wait for AuthKit redirect
      await session.callTool("browser_navigate", {
        url: "https://staging-console.pensar.dev/login",
      });
      await new Promise((r) => setTimeout(r, 3000));

      let snap = await session.callTool("browser_snapshot", {});
      let snapStr = typeof snap === "string" ? snap : JSON.stringify(snap);

      // Fill email
      const emailRef =
        snapStr.match(/textbox "Email".*?\[ref=(e\d+)\]/)?.[1] || "e16";
      await session.callTool("browser_type", {
        element: "Email",
        ref: emailRef,
        text: username,
        pressEnter: false,
      });

      // Click Continue
      const contRef =
        snapStr.match(/button "Continue".*?\[ref=(e\d+)\]/)?.[1] || "e17";
      await session.callTool("browser_click", {
        element: "Continue",
        ref: contRef,
      });

      // Wait for password page
      await new Promise((r) => setTimeout(r, 3000));
      snap = await session.callTool("browser_snapshot", {});
      snapStr = typeof snap === "string" ? snap : JSON.stringify(snap);

      // Fill password
      const pwRef = snapStr.match(/textbox "Password".*?\[ref=(e\d+)\]/)?.[1];
      expect(pwRef).toBeDefined();
      await session.callTool("browser_type", {
        element: "Password",
        ref: pwRef!,
        text: password,
        pressEnter: false,
      });

      // Click Sign in
      const signInRef = snapStr.match(/button "Sign in".*?\[ref=(e\d+)\]/)?.[1];
      expect(signInRef).toBeDefined();
      await session.callTool("browser_click", {
        element: "Sign in",
        ref: signInRef!,
      });

      // Wait for redirect to dashboard
      await new Promise((r) => setTimeout(r, 5000));

      // Extract cookies via browser_run_code -> page.context().cookies()
      const cookieResult = await session.callTool("browser_run_code", {
        code: `async (page) => { const cookies = await page.context().cookies(); return JSON.stringify(cookies); }`,
      });

      expect(typeof cookieResult).toBe("string");

      // Parse cookies from Playwright MCP output format
      const stripped = (cookieResult as string)
        .replace(/^###\s*Result\s*\n?/, "")
        .replace(/\n\n###[\s\S]*$/, "")
        .trim();

      const parsed = JSON.parse(stripped);
      const cookies: Array<{
        name: string;
        value: string;
        domain: string;
        httpOnly: boolean;
      }> = typeof parsed === "string" ? JSON.parse(parsed) : parsed;

      console.log(`Extracted ${cookies.length} cookies:`);
      cookies.forEach((c) =>
        console.log(`  ${c.name} (${c.domain}, httpOnly=${c.httpOnly})`),
      );

      expect(cookies.length).toBeGreaterThan(0);

      const httpOnlyCookies = cookies.filter((c) => c.httpOnly);
      expect(httpOnlyCookies.length).toBeGreaterThan(0);

      const sessionCookies = cookies.filter(
        (c) =>
          c.name === "wos-session" ||
          c.name === "session" ||
          c.name === "access-token",
      );
      expect(sessionCookies.length).toBeGreaterThan(0);
    },
    { timeout: 120_000 },
  );
});

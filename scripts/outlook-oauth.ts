/**
 * One-time helper to obtain Outlook (Microsoft Graph) OAuth2 tokens for testing.
 *
 * Usage:
 *   OUTLOOK_CLIENT_ID=<id> OUTLOOK_CLIENT_SECRET=<secret> bun run scripts/outlook-oauth.ts
 *
 * Opens a browser for consent, spins up a tiny local server to catch the
 * redirect, exchanges the code for tokens, and prints them.
 */

import { createServer } from "node:http";
import { URL } from "node:url";

const CLIENT_ID = process.env.OUTLOOK_CLIENT_ID;
const CLIENT_SECRET = process.env.OUTLOOK_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error(
    "Set OUTLOOK_CLIENT_ID and OUTLOOK_CLIENT_SECRET environment variables first.",
  );
  process.exit(1);
}
const clientId = CLIENT_ID;
const clientSecret = CLIENT_SECRET;

const PORT = 8457;
const REDIRECT_URI = `http://localhost:${PORT}/callback`;
const SCOPES = [
  "https://graph.microsoft.com/Mail.Read",
  "https://graph.microsoft.com/Mail.ReadWrite",
  "offline_access",
].join(" ");

const authUrl = new URL(
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
);
authUrl.searchParams.set("client_id", clientId);
authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("scope", SCOPES);
authUrl.searchParams.set("response_mode", "query");

console.log("\nOpen this URL in your browser:\n");
console.log(authUrl.toString());
console.log("\nWaiting for redirect...\n");

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

  if (url.pathname !== "/callback") {
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");

  if (error) {
    res.writeHead(400);
    res.end(
      `Error: ${error} – ${url.searchParams.get("error_description") ?? ""}`,
    );
    console.error(
      "Auth error:",
      error,
      url.searchParams.get("error_description"),
    );
    server.close();
    process.exit(1);
  }

  if (!code) {
    res.writeHead(400);
    res.end("Missing authorization code");
    return;
  }

  try {
    const tokenRes = await fetch(
      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: REDIRECT_URI,
          grant_type: "authorization_code",
          scope: SCOPES,
        }),
      },
    );

    const data = (await tokenRes.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      error?: string;
      error_description?: string;
    };

    if (data.error) {
      res.writeHead(400);
      res.end(`Error: ${data.error} – ${data.error_description}`);
      console.error("Token exchange failed:", data);
      process.exit(1);
    }

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<h2>Done! You can close this tab.</h2>");

    console.log("=".repeat(60));
    console.log("Add these to your .env:\n");
    console.log(`OUTLOOK_ACCESS_TOKEN=${data.access_token}`);
    console.log(`OUTLOOK_REFRESH_TOKEN=${data.refresh_token}`);
    console.log(`\nAccess token expires in ${data.expires_in}s.`);
    console.log(
      "The refresh token is long-lived — the adapter will auto-refresh.",
    );
    console.log("=".repeat(60));
  } catch (err) {
    res.writeHead(500);
    res.end("Token exchange failed");
    console.error(err);
  }

  server.close();
});

server.listen(PORT);

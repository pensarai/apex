/**
 * One-time helper to obtain Gmail OAuth2 tokens for testing.
 *
 * Usage:
 *   GMAIL_CLIENT_ID=<id> GMAIL_CLIENT_SECRET=<secret> bun run scripts/gmail-oauth.ts
 *
 * Opens a browser for consent, spins up a tiny local server to catch the
 * redirect, exchanges the code for tokens, and prints them.
 */

import { createServer } from "node:http";
import { URL } from "node:url";

const CLIENT_ID = process.env.GMAIL_CLIENT_ID;
const CLIENT_SECRET = process.env.GMAIL_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error(
    "Set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET environment variables first.",
  );
  process.exit(1);
}
const clientId = CLIENT_ID;
const clientSecret = CLIENT_SECRET;

const PORT = 8457;
const REDIRECT_URI = `http://localhost:${PORT}/callback`;
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
].join(" ");

const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
authUrl.searchParams.set("client_id", clientId);
authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("scope", SCOPES);
authUrl.searchParams.set("access_type", "offline");
authUrl.searchParams.set("prompt", "consent");

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
  if (!code) {
    res.writeHead(400);
    res.end("Missing authorization code");
    return;
  }

  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
      }),
    });

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
    console.log(`GMAIL_ACCESS_TOKEN=${data.access_token}`);
    console.log(`GMAIL_REFRESH_TOKEN=${data.refresh_token}`);
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

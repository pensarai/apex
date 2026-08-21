#!/usr/bin/env bun

/**
 * Pensar Login CLI
 *
 * Connect to Pensar Console for managed inference, directly from the CLI.
 * Mirrors the TUI /login flow using centralized auth logic from core/auth.
 *
 * Subcommands:
 *   pensar login           Start the login flow (or show status if already connected)
 *   pensar login status    Show current connection status
 *   pensar login logout    Disconnect from Pensar Console
 *
 * Legacy alias: `pensar auth` still works for backward compatibility
 */

import * as readline from "node:readline";
import { getPensarApiUrl, getPensarConsoleUrl } from "../core/api";
import {
  createWorkspaceSelection,
  disconnect,
  ensureValidToken,
  fetchWorkspaces,
  isConnected,
  pollForWorkspaceCreation,
  pollLegacyToken,
  pollWorkOSToken,
  pollWorkspaceSelection,
  selectWorkspace,
  startDeviceFlow,
} from "../core/auth";
import { config } from "../core/config";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function openUrl(url: string): void {
  try {
    const { spawn } =
      require("node:child_process") as typeof import("node:child_process");
    const platform = process.platform;
    let cmd: ReturnType<typeof spawn>;
    if (platform === "darwin") {
      cmd = spawn("open", [url]);
    } else if (platform === "win32") {
      cmd = spawn("cmd", ["/c", "start", url]);
    } else {
      cmd = spawn("xdg-open", [url]);
    }
    cmd.on("error", () => {}); // fire-and-forget — user sees the URL as fallback
  } catch {
    // Browser open failed — user will see the fallback URL
  }
}

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Resolve a workspace when the user has more than one, by handing selection off
 * to the browser. The CLI opens a Console page, the user picks there, and we
 * poll until the choice comes back — so login never blocks on a terminal prompt.
 *
 * Returns the chosen workspace id.
 */
async function selectWorkspaceInBrowser(
  apiUrl: string,
  accessToken: string,
): Promise<string> {
  const selection = await createWorkspaceSelection(apiUrl, accessToken);

  openUrl(selection.selectionUrl);

  console.log(
    `\nYou have multiple workspaces. Choose one in your browser to continue.\nIf the browser didn't open, visit:\n  ${selection.selectionUrl}\n\nWaiting for workspace selection...`,
  );

  return pollWorkspaceSelection(apiUrl, accessToken, selection.selectionId);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function login(): Promise<void> {
  const appConfig = await config.get();
  const hasStoredCredentials = isConnected(appConfig);
  const validToken = hasStoredCredentials
    ? await ensureValidToken({
        accessToken: appConfig.accessToken,
        refreshToken: appConfig.refreshToken,
        pensarAPIKey: appConfig.pensarAPIKey,
      })
    : null;

  if (validToken) {
    console.log("Already connected to Pensar Console.");
    if (appConfig.workspaceSlug) {
      console.log(`  Workspace: ${appConfig.workspaceSlug}`);
    }
    const answer = await prompt("\nReconnect? (y/N): ");
    if (answer.toLowerCase() !== "y") {
      return;
    }
  } else if (hasStoredCredentials) {
    console.log("Your saved Pensar Console session has expired. Reconnecting.");
  }

  console.log(
    "\nPensar Console — Managed Inference\nConnect for usage-based AI inference. No API keys needed.\n",
  );

  const apiUrl = getPensarApiUrl();
  const flowInfo = await startDeviceFlow(apiUrl);

  if (flowInfo.mode === "workos") {
    const { clientId, deviceInfo } = flowInfo;

    openUrl(deviceInfo.verification_uri_complete);

    console.log(
      `A browser window should have opened.\nIf not, open this URL:\n  ${deviceInfo.verification_uri_complete}\n\nYour code: ${deviceInfo.user_code}\n\nWaiting for browser authorization...`,
    );

    const tokens = await pollWorkOSToken({
      clientId,
      deviceCode: deviceInfo.device_code,
      interval: deviceInfo.interval,
      expiresIn: deviceInfo.expires_in,
    });

    await config.update({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    });

    console.log("\nAuthenticated successfully. Fetching workspaces...");
    await handleWorkspaces(apiUrl, tokens.accessToken);
  } else {
    const { deviceInfo } = flowInfo;

    openUrl(deviceInfo.verificationUriComplete);

    console.log(
      `A browser window should have opened.\nIf not, open this URL:\n  ${deviceInfo.verificationUriComplete}\n\nYour code: ${deviceInfo.userCode}\n\nWaiting for browser authorization...`,
    );

    const data = await pollLegacyToken({
      apiUrl,
      deviceCode: deviceInfo.deviceCode,
      interval: deviceInfo.interval,
      expiresIn: deviceInfo.expiresIn,
      clientId: flowInfo.clientId,
    });

    const apiKey = data.apiKey;
    if (!apiKey) {
      throw new Error("Pensar Console did not return an API key");
    }

    await config.update({
      pensarAPIKey: apiKey,
      gatewaySigningKey: data.signingKey ?? null,
    });

    if (data.workspace) {
      await config.update({
        workspaceId: data.workspace.id,
        workspaceSlug: data.workspace.slug,
      });
    }

    console.log("\n✓ Connected to Pensar Console");
    if (data.workspace) {
      console.log(
        `  Workspace: ${data.workspace.name} (${data.workspace.slug})`,
      );
    }
    if (data.credits) {
      console.log(`  Credits: $${data.credits.balance.toFixed(2)}`);
    }
  }
}

async function handleWorkspaces(
  apiUrl: string,
  accessToken: string,
): Promise<void> {
  const wsResult = await fetchWorkspaces(apiUrl, accessToken);
  let workspaces = wsResult.workspaces;

  // Use dynamic consoleUrl from server if provided
  const consoleUrl = wsResult.consoleUrl ?? getPensarConsoleUrl();

  if (workspaces.length === 0) {
    console.log(
      `\nNo workspaces found. Opening browser to create one...\nIf the browser didn't open, visit: ${consoleUrl}/create-workspace?redirect=/credits\n`,
    );
    openUrl(`${consoleUrl}/create-workspace?redirect=/credits`);
    console.log("Waiting for workspace creation...");
    workspaces = await pollForWorkspaceCreation(apiUrl, accessToken);
  }

  let workspaceId: string;
  if (workspaces.length === 1) {
    const onlyWorkspace = workspaces[0];
    if (!onlyWorkspace) {
      throw new Error("No workspace available after workspace lookup");
    }
    workspaceId = onlyWorkspace.id;
  } else {
    workspaceId = await selectWorkspaceInBrowser(apiUrl, accessToken);
  }

  const result = await selectWorkspace(apiUrl, accessToken, workspaceId);
  const workspace = result.workspace;

  await config.update({
    workspaceId: workspace.id,
    workspaceSlug: workspace.slug,
    gatewaySigningKey: result.signingKey ?? null,
  });

  console.log(
    `\n✓ Connected to Pensar Console\n  Workspace: ${workspace.name} (${workspace.slug})\n  Credits: $${result.billing.balance.toFixed(2)}`,
  );

  const needsBillingSetup =
    !result.billing.ready && result.billing.balance <= 0 && !!result.billingUrl;

  if (needsBillingSetup && result.billingUrl) {
    console.log(
      `\n⚠ Your workspace billing setup is not ready yet. Finish setup at:\n  ${result.billingUrl}`,
    );
  } else if (result.billing.balance < 1) {
    const billingUrl = `${getPensarConsoleUrl()}/${workspace.slug}/settings/billing`;
    console.log(
      `\n⚠ Low credit balance. We recommend at least $30 for uninterrupted pentests.\n  Add credits: ${billingUrl}`,
    );
  }

  console.log(
    "\nPensar models are now available. Run `pensar` to get started.",
  );
}

async function logout(): Promise<void> {
  const appConfig = await config.get();

  if (!isConnected(appConfig)) {
    console.log("Not currently connected to Pensar Console.");
    return;
  }

  await disconnect();
  console.log("✓ Disconnected from Pensar Console.");
}

async function status(): Promise<void> {
  const appConfig = await config.get();

  if (!isConnected(appConfig)) {
    console.log(
      "Not connected to Pensar Console.\n\nRun `pensar login` to connect.",
    );
    return;
  }

  const validToken = await ensureValidToken({
    accessToken: appConfig.accessToken,
    refreshToken: appConfig.refreshToken,
    pensarAPIKey: appConfig.pensarAPIKey,
  });
  if (!validToken) {
    console.log(
      "Your Pensar Console session has expired.\n\nRun `pensar login` to reconnect.",
    );
    return;
  }

  // If using an API key without stored workspace info, resolve it from the server
  if (
    !appConfig.accessToken &&
    appConfig.pensarAPIKey &&
    !appConfig.workspaceSlug
  ) {
    try {
      const apiUrl = getPensarApiUrl();
      const res = await fetch(`${apiUrl}/auth/validate`, {
        headers: { Authorization: `Bearer ${appConfig.pensarAPIKey}` },
      });
      if (res.ok) {
        const data = (await res.json()) as {
          workspace?: { id: string; name: string; slug: string };
        };
        if (data.workspace) {
          await config.update({
            workspaceId: data.workspace.id,
            workspaceSlug: data.workspace.slug,
          });
          appConfig.workspaceId = data.workspace.id;
          appConfig.workspaceSlug = data.workspace.slug;
        }
      }
    } catch {
      // Non-fatal — we'll just show "not set"
    }
  }

  const authMethod = appConfig.accessToken ? "WorkOS" : "API key";
  console.log(
    `✓ Connected to Pensar Console\n  Workspace: ${appConfig.workspaceSlug ?? "not set"}\n  Auth: ${authMethod}`,
  );
}

function showHelp(): void {
  console.log(`Pensar Login — Connect to Pensar Console

Usage:
  pensar login             Login to Pensar Console (or show status if connected)
  pensar login status      Show connection status
  pensar login logout      Disconnect from Pensar Console

Legacy alias: 'pensar auth' still works for backward compatibility

Options:
  -h, --help               Show this help message`);
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const subcommand = args[0];

  if (subcommand === "help" || subcommand === "--help" || subcommand === "-h") {
    showHelp();
    return;
  }

  try {
    if (!subcommand || subcommand === "login") {
      await login();
    } else if (subcommand === "logout") {
      await logout();
    } else if (subcommand === "status") {
      await status();
    } else {
      console.error(`Unknown auth subcommand: ${subcommand}`);
      console.error("Run 'pensar login --help' for usage information");
      process.exit(1);
    }
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}

main();

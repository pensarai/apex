#!/usr/bin/env bun

/**
 * Pensar Auth CLI
 *
 * Connect to Pensar Console for managed inference, directly from the CLI.
 * Mirrors the TUI /auth flow using centralized auth logic from core/auth.
 *
 * Subcommands:
 *   pensar auth            Start the login flow (or show status if already connected)
 *   pensar auth login      Start the login flow
 *   pensar auth logout     Disconnect from Pensar Console
 *   pensar auth status     Show current connection status
 */

import { config } from "../core/config";
import { getPensarApiUrl, getPensarConsoleUrl } from "../core/api/constants";
import {
  isConnected,
  disconnect,
  startDeviceFlow,
  pollWorkOSToken,
  pollLegacyToken,
  fetchWorkspaces,
  pollForWorkspaceCreation,
  selectWorkspace,
} from "../core/auth";
import type { WorkspaceInfo } from "../core/auth";
import * as readline from "readline";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function openUrl(url: string): void {
  try {
    const platform = process.platform;
    if (platform === "darwin") {
      Bun.spawn(["open", url]);
    } else if (platform === "win32") {
      Bun.spawn(["cmd", "/c", "start", url]);
    } else {
      Bun.spawn(["xdg-open", url]);
    }
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

async function promptWorkspaceSelection(
  workspaces: WorkspaceInfo[],
): Promise<WorkspaceInfo> {
  console.log("\nSelect a workspace:\n");
  workspaces.forEach((ws, i) => {
    console.log(
      `  ${i + 1}. ${ws.name} (${ws.slug}) — $${ws.balance.toFixed(2)}`,
    );
  });

  const answer = await prompt(`\nEnter number (1-${workspaces.length}): `);
  const index = parseInt(answer, 10) - 1;

  if (isNaN(index) || index < 0 || index >= workspaces.length) {
    console.error("Invalid selection.");
    process.exit(1);
  }

  return workspaces[index]!;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function login(): Promise<void> {
  const appConfig = await config.get();

  if (isConnected(appConfig)) {
    console.log("Already connected to Pensar Console.");
    if (appConfig.workspaceSlug) {
      console.log(`  Workspace: ${appConfig.workspaceSlug}`);
    }
    const answer = await prompt("\nReconnect? (y/N): ");
    if (answer.toLowerCase() !== "y") {
      return;
    }
  }

  console.log("\nPensar Console — Managed Inference");
  console.log("Connect for usage-based AI inference. No API keys needed.\n");

  const apiUrl = getPensarApiUrl();
  const flowInfo = await startDeviceFlow(apiUrl);

  if (flowInfo.mode === "workos") {
    const { clientId, deviceInfo } = flowInfo;

    openUrl(deviceInfo.verification_uri_complete);

    console.log("A browser window should have opened.");
    console.log(
      `If not, open this URL:\n  ${deviceInfo.verification_uri_complete}\n`,
    );
    console.log(`Your code: ${deviceInfo.user_code}\n`);
    console.log("Waiting for browser authorization...");

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

    console.log("A browser window should have opened.");
    console.log(
      `If not, open this URL:\n  ${deviceInfo.verificationUriComplete}\n`,
    );
    console.log(`Your code: ${deviceInfo.userCode}\n`);
    console.log("Waiting for browser authorization...");

    const data = await pollLegacyToken({
      apiUrl,
      deviceCode: deviceInfo.deviceCode,
      interval: deviceInfo.interval,
      expiresIn: deviceInfo.expiresIn,
    });

    await config.update({
      pensarAPIKey: data.apiKey!,
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
  let workspaces = await fetchWorkspaces(apiUrl, accessToken);

  if (workspaces.length === 0) {
    const consoleUrl = getPensarConsoleUrl();
    console.log("\nNo workspaces found. Opening browser to create one...");
    console.log(`If the browser didn't open, visit: ${consoleUrl}/credits\n`);
    openUrl(`${consoleUrl}/credits`);
    console.log("Waiting for workspace creation...");
    workspaces = await pollForWorkspaceCreation(apiUrl, accessToken);
  }

  let workspace: WorkspaceInfo;
  if (workspaces.length === 1) {
    workspace = workspaces[0]!;
  } else {
    workspace = await promptWorkspaceSelection(workspaces);
  }

  const result = await selectWorkspace(apiUrl, accessToken, workspace.id);

  await config.update({
    workspaceId: workspace.id,
    workspaceSlug: workspace.slug,
    gatewaySigningKey: result.signingKey ?? null,
  });

  console.log("\n✓ Connected to Pensar Console");
  console.log(`  Workspace: ${workspace.name} (${workspace.slug})`);
  console.log(`  Credits: $${result.billing.balance.toFixed(2)}`);

  if (!result.confirmed && result.billingUrl) {
    console.log(
      `\n⚠ Your workspace needs credits. Add them at:\n  ${result.billingUrl}`,
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
    console.log("Not connected to Pensar Console.");
    console.log("\nRun `pensar auth login` to connect.");
    return;
  }

  console.log("✓ Connected to Pensar Console");
  if (appConfig.workspaceSlug) {
    console.log(`  Workspace: ${appConfig.workspaceSlug}`);
  }
  if (appConfig.accessToken) {
    console.log("  Auth: WorkOS (modern)");
  } else {
    console.log("  Auth: API key (legacy)");
  }
}

function showHelp(): void {
  console.log("Pensar Auth — Connect to Pensar Console\n");
  console.log("Usage:");
  console.log(
    "  pensar auth              Login to Pensar Console (or show status if connected)",
  );
  console.log("  pensar auth login        Login to Pensar Console");
  console.log("  pensar auth logout       Disconnect from Pensar Console");
  console.log("  pensar auth status       Show connection status");
  console.log();
  console.log("Options:");
  console.log("  -h, --help               Show this help message");
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
      console.error("Run 'pensar auth --help' for usage information");
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

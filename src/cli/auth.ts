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

import * as readline from "readline";
import { getPensarApiUrl, getPensarConsoleUrl } from "../core/api";
import type { WorkspaceInfo } from "../core/auth";
import {
  disconnect,
  fetchWorkspaces,
  isConnected,
  pollForWorkspaceCreation,
  pollLegacyToken,
  pollWorkOSToken,
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
      require("child_process") as typeof import("child_process");
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

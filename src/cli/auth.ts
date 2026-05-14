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

function hasFlag(flag: string): boolean {
  return process.argv.includes(flag);
}

function getArg(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 && idx + 1 < process.argv.length
    ? process.argv[idx + 1]
    : undefined;
}

function isTTY(): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true;
}

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

function findWorkspaceBySlugOrId(
  workspaces: WorkspaceInfo[],
  slugOrId: string,
): WorkspaceInfo | undefined {
  return workspaces.find((ws) => ws.slug === slugOrId || ws.id === slugOrId);
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

  if (Number.isNaN(index) || index < 0 || index >= workspaces.length) {
    console.error("Invalid selection.");
    process.exit(1);
  }

  const selected = workspaces[index];
  if (!selected) {
    console.error("Invalid selection.");
    process.exit(1);
  }

  return selected;
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

    if (!data.apiKey) {
      throw new Error("Authentication failed: no API key received");
    }

    await config.update({
      pensarAPIKey: data.apiKey,
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
  const jsonOutput = hasFlag("--json");

  // Use dynamic consoleUrl from server if provided
  const consoleUrl = wsResult.consoleUrl ?? getPensarConsoleUrl();

  if (workspaces.length === 0) {
    if (jsonOutput) {
      console.log(
        JSON.stringify({
          success: false,
          error: "no_workspaces",
          message: "No workspaces found. Create one to continue.",
          consoleUrl: `${consoleUrl}/create-workspace?redirect=/credits`,
        }),
      );
      process.exit(1);
    }

    console.log(
      `\nNo workspaces found. Opening browser to create one...\nIf the browser didn't open, visit: ${consoleUrl}/create-workspace?redirect=/credits\n`,
    );
    openUrl(`${consoleUrl}/create-workspace?redirect=/credits`);
    console.log("Waiting for workspace creation...");
    workspaces = await pollForWorkspaceCreation(apiUrl, accessToken);
  }

  let workspace: WorkspaceInfo | undefined;
  const workspaceFlag = getArg("--workspace");
  const workspaceEnv = process.env.PENSAR_WORKSPACE;
  const workspaceSpec = workspaceFlag ?? workspaceEnv;

  if (workspaceSpec) {
    const found = findWorkspaceBySlugOrId(workspaces, workspaceSpec);
    if (!found) {
      if (jsonOutput) {
        console.log(
          JSON.stringify({
            success: false,
            error: "workspace_not_found",
            message: `Workspace '${workspaceSpec}' not found`,
            availableWorkspaces: workspaces.map((ws) => ({
              id: ws.id,
              slug: ws.slug,
              name: ws.name,
            })),
          }),
        );
      } else {
        console.error(`\nError: Workspace '${workspaceSpec}' not found.`);
        console.error("\nAvailable workspaces:");
        workspaces.forEach((ws) => {
          console.error(`  - ${ws.slug} (${ws.name})`);
        });
      }
      process.exit(1);
    }
    workspace = found;
  } else if (workspaces.length === 1) {
    const onlyWorkspace = workspaces[0];
    if (!onlyWorkspace) {
      throw new Error("No workspace available after workspace lookup");
    }
    workspace = onlyWorkspace;
  } else {
    if (!isTTY()) {
      if (jsonOutput) {
        console.log(
          JSON.stringify({
            success: false,
            error: "workspace_selection_required",
            message:
              "Multiple workspaces available. Specify one with --workspace or PENSAR_WORKSPACE",
            availableWorkspaces: workspaces.map((ws) => ({
              id: ws.id,
              slug: ws.slug,
              name: ws.name,
              balance: ws.balance,
            })),
          }),
        );
      } else {
        console.error(
          "\nError: Multiple workspaces available, but running in non-interactive mode.",
        );
        console.error(
          "Specify a workspace using --workspace <slug> or set PENSAR_WORKSPACE=<slug>\n",
        );
        console.error("Available workspaces:");
        workspaces.forEach((ws) => {
          console.error(`  - ${ws.slug} (${ws.name})`);
        });
      }
      process.exit(1);
    }
    workspace = await promptWorkspaceSelection(workspaces);
  }

  if (!workspace) {
    throw new Error("No workspace selected");
  }

  const result = await selectWorkspace(apiUrl, accessToken, workspace.id);

  await config.update({
    workspaceId: workspace.id,
    workspaceSlug: workspace.slug,
    gatewaySigningKey: result.signingKey ?? null,
  });

  const needsBillingSetup =
    !result.billing.ready && result.billing.balance <= 0 && !!result.billingUrl;
  const billingUrl =
    result.billingUrl ??
    `${getPensarConsoleUrl()}/${workspace.slug}/settings/billing`;

  if (jsonOutput) {
    console.log(
      JSON.stringify({
        success: true,
        workspace: {
          id: workspace.id,
          slug: workspace.slug,
          name: workspace.name,
        },
        billing: {
          balance: result.billing.balance,
          ready: result.billing.ready,
          hasPaymentMethod: result.billing.hasPaymentMethod,
          billingUrl,
          needsSetup: needsBillingSetup,
        },
      }),
    );
  } else {
    console.log(
      `\n✓ Connected to Pensar Console\n  Workspace: ${workspace.name} (${workspace.slug})\n  Credits: $${result.billing.balance.toFixed(2)}`,
    );

    if (needsBillingSetup && result.billingUrl) {
      console.log(
        `\n⚠ Your workspace billing setup is not ready yet. Finish setup at:\n  ${result.billingUrl}`,
      );
    } else if (result.billing.balance < 1) {
      console.log(
        `\n⚠ Low credit balance. We recommend at least $30 for uninterrupted pentests.\n  Add credits: ${billingUrl}`,
      );
    }

    console.log(
      "\nPensar models are now available. Run `pensar` to get started.",
    );
  }
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
  const jsonOutput = hasFlag("--json");

  if (!isConnected(appConfig)) {
    if (jsonOutput) {
      console.log(JSON.stringify({ connected: false }));
    } else {
      console.log(
        "Not connected to Pensar Console.\n\nRun `pensar login` to connect.",
      );
    }
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

  if (jsonOutput) {
    console.log(
      JSON.stringify({
        connected: true,
        workspace: appConfig.workspaceSlug ?? null,
        workspaceId: appConfig.workspaceId ?? null,
        authMethod,
      }),
    );
  } else {
    console.log(
      `✓ Connected to Pensar Console\n  Workspace: ${appConfig.workspaceSlug ?? "not set"}\n  Auth: ${authMethod}`,
    );
  }
}

async function listWorkspaces(): Promise<void> {
  const appConfig = await config.get();
  const jsonOutput = hasFlag("--json");

  if (!isConnected(appConfig)) {
    if (jsonOutput) {
      console.log(
        JSON.stringify({
          success: false,
          error: "not_connected",
          message: "Not connected to Pensar Console",
        }),
      );
    } else {
      console.error(
        "Error: Not connected to Pensar Console.\n\nRun `pensar login` first.",
      );
    }
    process.exit(1);
  }

  if (!appConfig.accessToken) {
    if (jsonOutput) {
      console.log(
        JSON.stringify({
          success: false,
          error: "workos_auth_required",
          message:
            "Listing workspaces requires WorkOS authentication. Please re-authenticate.",
        }),
      );
    } else {
      console.error(
        "Error: Listing workspaces requires WorkOS authentication.\nPlease run `pensar login` to re-authenticate.",
      );
    }
    process.exit(1);
  }

  const apiUrl = getPensarApiUrl();
  const wsResult = await fetchWorkspaces(apiUrl, appConfig.accessToken);

  if (jsonOutput) {
    console.log(
      JSON.stringify({
        success: true,
        workspaces: wsResult.workspaces.map((ws) => ({
          id: ws.id,
          slug: ws.slug,
          name: ws.name,
          balance: ws.balance,
          hasPaymentMethod: ws.hasPaymentMethod,
        })),
      }),
    );
  } else {
    if (wsResult.workspaces.length === 0) {
      console.log("No workspaces available.");
    } else {
      console.log("\nAvailable workspaces:\n");
      wsResult.workspaces.forEach((ws) => {
        const current =
          ws.slug === appConfig.workspaceSlug ||
          ws.id === appConfig.workspaceId
            ? " (current)"
            : "";
        console.log(
          `  ${ws.slug.padEnd(20)} ${ws.name.padEnd(30)} $${ws.balance.toFixed(2)}${current}`,
        );
      });
      console.log();
    }
  }
}

function showHelp(): void {
  console.log(`Pensar Login — Connect to Pensar Console

Usage:
  pensar login                    Login to Pensar Console (or show status if connected)
  pensar login status             Show connection status
  pensar login logout             Disconnect from Pensar Console
  pensar login list-workspaces    List available workspaces

Legacy alias: 'pensar auth' still works for backward compatibility

Options:
  --workspace <slug|id>    Select a specific workspace by slug or ID
  --json                   Output structured JSON instead of human-readable text
  -h, --help               Show this help message

Environment Variables:
  PENSAR_WORKSPACE         Default workspace slug or ID (lower precedence than --workspace)`);
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
    } else if (subcommand === "list-workspaces") {
      await listWorkspaces();
    } else {
      const jsonOutput = hasFlag("--json");
      if (jsonOutput) {
        console.log(
          JSON.stringify({
            success: false,
            error: "unknown_subcommand",
            message: `Unknown subcommand: ${subcommand}`,
          }),
        );
      } else {
        console.error(`Unknown auth subcommand: ${subcommand}`);
        console.error("Run 'pensar login --help' for usage information");
      }
      process.exit(1);
    }
  } catch (err) {
    const jsonOutput = hasFlag("--json");
    if (jsonOutput) {
      console.log(
        JSON.stringify({
          success: false,
          error: "exception",
          message: err instanceof Error ? err.message : String(err),
        }),
      );
    } else {
      console.error(
        `\nError: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    process.exit(1);
  }
}

main();

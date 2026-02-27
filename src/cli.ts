#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * Unified entry point for standalone binary compilation.
 */

import packageJson from "../package.json";
import { getCurrentVersion, upgrade } from "./core/installation";
import { config as loadDotenv } from "dotenv";
import { runPentestAgent } from "./core/api/blackboxPentest";
import { runTargetedPentestAgent } from "./core/api/targetedPentest";
import { sessions } from "./core/session";
import { get as getConfig } from "./core/config";
import type { AIModel } from "./core/ai";

const args = process.argv.slice(2);
const command = args[0];
const version = packageJson.version;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getArg(flag: string, argv = args): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 ? argv[idx + 1] : undefined;
}

function getArgRequired(flag: string, argv = args): string {
  const val = getArg(flag, argv);
  if (!val) {
    console.error(`Error: ${flag} is required`);
    process.exit(1);
  }
  return val;
}

function getAllArgs(flag: string, argv = args): string[] {
  const values: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === flag && argv[i + 1]) {
      values.push(argv[i + 1]!);
    }
  }
  return values;
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function showHelp() {
  console.log("Pensar - AI-Powered Penetration Testing CLI");
  console.log();
  console.log("Usage:");
  console.log("  pensar                             Launch the TUI");
  console.log(
    "  pensar pentest [options]            Run a full pentest orchestration",
  );
  console.log(
    "  pensar targeted-pentest [options]   Run a targeted pentest on a single target",
  );
  console.log(
    "  pensar upgrade                      Update pensar to the latest version",
    "  pensar doctor                      Check dependencies and install missing tools",
  );
  console.log("  pensar help                         Show this help message");
  console.log("  pensar version                      Show version number");
  console.log();
  console.log("pentest options:");
  console.log("  --target <url>     (required) Target URL / domain / IP");
  console.log(
    "  --cwd <path>       Source code path — enables whitebox attack surface",
  );
  console.log("  --model <model>    AI model (default: claude-sonnet-4-5)");
  console.log();
  console.log("targeted-pentest options:");
  console.log("  --target <url>          (required) Target URL / domain / IP");
  console.log(
    "  --objective <text>      (required, repeatable) Testing objective",
  );
  console.log(
    "  --model <model>         AI model (default: claude-sonnet-4-5)",
  );
  console.log();
  console.log("Global options:");
  console.log("  -h, --help         Show this help message");
  console.log("  -v, --version      Show version number");
  console.log();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function runPentest() {
  loadDotenv();

  const target = getArgRequired("--target");
  const cwd = getArg("--cwd");
  const model = (getArg("--model") ?? "claude-sonnet-4-5") as AIModel;

  console.log("=".repeat(60));
  console.log("PENTEST ORCHESTRATION");
  console.log("=".repeat(60));
  console.log(`Target:  ${target}`);
  if (cwd) console.log(`Cwd:     ${cwd} (whitebox)`);
  console.log(`Model:   ${model}`);
  console.log();

  const pensarConfig = await getConfig();

  const session = await sessions.create({
    name: cwd ? "Whitebox Pentest" : "Blackbox Pentest",
    targets: [target],
    ...(cwd ? { config: { cwd } } : {}),
  });

  const { findings, findingsPath, pocsPath, reportPath } =
    await runPentestAgent({
      target,
      ...(cwd ? { cwd } : {}),
      session,
      model,
      authConfig: {
        anthropicAPIKey: pensarConfig.anthropicAPIKey ?? undefined,
        openAiAPIKey: pensarConfig.openAiAPIKey ?? undefined,
        openRouterAPIKey: pensarConfig.openRouterAPIKey ?? undefined,
        local: pensarConfig.localModelUrl
          ? { baseURL: pensarConfig.localModelUrl }
          : undefined,
      },
      callbacks: {
        onTextDelta: (d) => process.stdout.write(d.text),
        onToolCall: (d) => console.log(`\n→ ${d.toolName}`),
        onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
        onError: (e) => console.error("Error:", e),
      },
    });

  console.log();
  console.log("=".repeat(60));
  console.log("RESULTS");
  console.log("=".repeat(60));
  console.log(`Findings:  ${findings.length}`);
  console.log(`Path:      ${findingsPath}`);
  console.log(`POCs:      ${pocsPath}`);
  if (reportPath) console.log(`Report:    ${reportPath}`);
}

async function runTargetedPentest() {
  loadDotenv();

  const target = getArgRequired("--target");
  const objectives = getAllArgs("--objective");
  const model = (getArg("--model") ?? "claude-sonnet-4-5") as AIModel;

  if (objectives.length === 0) {
    console.error("Error: at least one --objective is required");
    process.exit(1);
  }

  console.log("=".repeat(60));
  console.log("TARGETED PENTEST");
  console.log("=".repeat(60));
  console.log(`Target:  ${target}`);
  console.log(`Model:   ${model}`);
  console.log("Objectives:");
  objectives.forEach((o, i) => console.log(`  ${i + 1}. ${o}`));
  console.log();

  const pensarConfig = await getConfig();

  const session = await sessions.create({
    name: "Targeted Pentest",
    targets: [target],
  });

  const { findings, findingsPath, pocsPath } = await runTargetedPentestAgent({
    target,
    objectives,
    session,
    model,
    authConfig: {
      anthropicAPIKey: pensarConfig.anthropicAPIKey ?? undefined,
      openAiAPIKey: pensarConfig.openAiAPIKey ?? undefined,
      openRouterAPIKey: pensarConfig.openRouterAPIKey ?? undefined,
      local: pensarConfig.localModelUrl
        ? { baseURL: pensarConfig.localModelUrl }
        : undefined,
    },
  });

  console.log();
  console.log("=".repeat(60));
  console.log("RESULTS");
  console.log("=".repeat(60));
  console.log(`Findings:  ${findings.length}`);
  console.log(`Path:      ${findingsPath}`);
  console.log(`POCs:      ${pocsPath}`);
}

async function runUpgrade() {
  const currentVersion = getCurrentVersion();
  console.log(`Current version: v${currentVersion}`);
  console.log("Checking for updates...");

  const result = await upgrade({ interactive: true });
  console.log();
  console.log(result.message);

  process.exit(result.success ? 0 : 1);
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

if (command === "version" || command === "--version" || command === "-v") {
  console.log(`v${version}`);
} else if (command === "help" || command === "--help" || command === "-h") {
  showHelp();
} else if (command === "upgrade" || command === "update") {
  await runUpgrade();
} else if (command === "pentest") {
  await runPentest();
} else if (command === "targeted-pentest") {
  await runTargetedPentest();
} else if (command === "doctor") {
  // eslint-disable-next-line no-restricted-syntax -- lazy load to reduce CLI startup time
  const { runDoctor } = await import("./core/doctor");
  await runDoctor();
} else if (args.length === 0) {
  // eslint-disable-next-line no-restricted-syntax -- lazy load TUI to reduce CLI startup time
  await import("./tui/index.tsx");
} else {
  console.error(`Error: Unknown command '${command}'`);
  console.error();
  console.error("Run 'pensar --help' for usage information");
  process.exit(1);
}

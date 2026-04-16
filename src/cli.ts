#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * Unified entry point for standalone binary compilation.
 * All modules are statically imported so Bun can bundle them.
 */

import packageJson from "../package.json";
import { getCurrentVersion, upgrade } from "./core/installation";
import { buildAuthConfig } from "./core/ai/utils";
import { resolvePentestMode } from "./core/cli/pentestMode";
import { AgentEventBus } from "./core/eventBus";
import type { SessionInfo } from "./core/session";
import {
  resolveFlagValue,
  resolveThreatModelPrompt,
  combinePromptParts,
} from "./tui/utils/command-flags";

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

function hasFlag(flag: string, argv = args): boolean {
  return argv.includes(flag);
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

function attachCliAgentStreamListeners(bus: AgentEventBus): void {
  bus.on("text-delta", (d) => process.stdout.write(d.text));
  bus.on("tool-call-complete", (d) => console.log(`\n→ ${d.toolName}`));
  bus.on("tool-result", (d) => console.log(`✓ ${d.toolName} completed`));
  bus.on("error", (d) => console.error("Error:", d.error));
}

async function createInstrumentedBus(
  session: SessionInfo,
): Promise<{ bus: AgentEventBus; cleanup: () => Promise<void> }> {
  const bus = new AgentEventBus();
  attachCliAgentStreamListeners(bus);
  const { attachWandbToEventBus } =
    await import("./core/integrations/wandb/upload");
  const wandbCleanup = await attachWandbToEventBus(session, bus).catch((e) => {
    console.warn("[wandb] Tracing disabled:", (e as Error).message);
    return null;
  });
  return { bus, cleanup: async () => wandbCleanup?.() };
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function showHelp() {
  console.log(`Pensar - AI-Powered Penetration Testing CLI

Usage:
  pensar                             Launch the TUI
  pensar pentest [options]            Run a full pentest orchestration
  pensar targeted-pentest [options]   Run a targeted pentest on a single target
  pensar threat-model [options]       Generate application-centric threat model
  pensar auth                         Connect to Pensar Console
  pensar uninstall                    Uninstall Pensar (keeps sessions, memories, skills)
  pensar projects                     List workspace projects
  pensar pentests                     List and manage pentests
  pensar issues                       List and manage security issues
  pensar fixes                        View security fixes
  pensar logs                         View agent execution logs
  pensar upgrade                      Update pensar to the latest version
  pensar doctor                       Check dependencies and install missing tools
  pensar help                         Show this help message
  pensar version                      Show version number

pentest options:
  --target <url>           (required) Target URL / domain / IP
  --cwd <path>             Source code path — enables whitebox attack surface
  --mode <mode>            Pentest mode: exfil (pivoting & flag extraction)
  --model <model>          AI model (default: claude-sonnet-4-5)
  --extended-thinking       Enable extended thinking for supported models
  --task-driven             Enable task-driven architecture (experimental)
  --prompt <text|@file>    Guidance for the pentest agent (inline text or @filepath)
  --threat-model <text|@file>  Threat model to guide the pentest (inline or @filepath)

targeted-pentest options:
  --target <url>          (required) Target URL / domain / IP
  --objective <text>      (required, repeatable) Testing objective
  --model <model>         AI model (default: claude-sonnet-4-5)

threat-model options:
  --output, -o <path>  Output file path (default: ./threat-model.md)
  --model <model>      AI model (default: claude-sonnet-4-5)

Global options:
  -h, --help         Show this help message
  -v, --version      Show version number
`);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function runPentest() {
  const { config } = await import("dotenv");
  config();

  const { runPentestAgent } = await import("./core/api/blackboxPentest");
  const { sessions } = await import("./core/session");
  const { config: appConfig } = await import("./core/config");
  const { getDefaultModelForConfig } = await import("./core/providers/utils");
  type AIModel = import("./core/ai").AIModel;

  const target = getArgRequired("--target");
  const cwd = getArg("--cwd");
  const mode = getArg("--mode");
  const promptRaw = getArg("--prompt");
  const threatModelRaw = getArg("--threat-model");
  const enableThinking = hasFlag("--extended-thinking");
  const taskDriven = hasFlag("--task-driven");

  // Resolve and combine threat model + prompt
  const resolvedTm = threatModelRaw
    ? resolveThreatModelPrompt(threatModelRaw)
    : undefined;
  const resolvedPrompt = promptRaw ? resolveFlagValue(promptRaw) : undefined;
  const prompt = combinePromptParts(resolvedTm, resolvedPrompt);

  const pensarConfig = await appConfig.get();
  const dynamicDefault =
    getDefaultModelForConfig(pensarConfig)?.id ?? "claude-sonnet-4-5";
  const model = (getArg("--model") ?? dynamicDefault) as AIModel;
  const { exfilMode, warning: modeWarning } = resolvePentestMode(mode);

  if (modeWarning) {
    console.warn(modeWarning);
  }

  const sep = "=".repeat(60);
  console.log(`${sep}
PENTEST ORCHESTRATION
${sep}
Target:  ${target}${cwd ? `\nCwd:     ${cwd} (whitebox)` : ""}${exfilMode ? "\nMode:    exfil" : ""}
Model:   ${model}${enableThinking ? "\nThinking: enabled" : ""}${taskDriven ? "\nTask-driven: enabled" : ""}
`);

  const session = await sessions.create({
    name: cwd ? "Whitebox Pentest" : "Blackbox Pentest",
    targets: [target],
    config: {
      ...(cwd ? { cwd } : {}),
      ...(exfilMode ? { exfilMode: true } : {}),
      ...(prompt ? { prompt } : {}),
      ...(taskDriven ? { taskDriven: true } : {}),
    },
  });

  const { bus: pentestBus, cleanup: wandbCleanup } =
    await createInstrumentedBus(session);

  try {
    const { findings, findingsPath, pocsPath, reportPath } =
      await runPentestAgent({
        target,
        ...(cwd ? { cwd } : {}),
        session,
        model,
        enableThinking,
        authConfig: buildAuthConfig(pensarConfig),
        eventBus: pentestBus,
      });

    console.log(`
${sep}
RESULTS
${sep}
Findings:  ${findings.length}
Path:      ${findingsPath}
POCs:      ${pocsPath}${reportPath ? `\nReport:    ${reportPath}` : ""}`);
  } finally {
    await wandbCleanup();
  }
}

async function runTargetedPentest() {
  const { config } = await import("dotenv");
  config();

  const { runTargetedPentestAgent } =
    await import("./core/api/targetedPentest");
  const { sessions } = await import("./core/session");
  const { config: appConfig } = await import("./core/config");
  const { getDefaultModelForConfig } = await import("./core/providers/utils");
  type AIModel = import("./core/ai").AIModel;

  const target = getArgRequired("--target");
  const objectives = getAllArgs("--objective");

  const pensarConfig = await appConfig.get();
  const dynamicDefault =
    getDefaultModelForConfig(pensarConfig)?.id ?? "claude-sonnet-4-5";
  const model = (getArg("--model") ?? dynamicDefault) as AIModel;

  if (objectives.length === 0) {
    console.error("Error: at least one --objective is required");
    process.exit(1);
  }

  const sep = "=".repeat(60);
  const objectivesList = objectives
    .map((o, i) => `  ${i + 1}. ${o}`)
    .join("\n");
  console.log(`${sep}
TARGETED PENTEST
${sep}
Target:  ${target}
Model:   ${model}
Objectives:
${objectivesList}
`);

  const session = await sessions.create({
    name: "Targeted Pentest",
    targets: [target],
  });

  const { bus: targetedBus, cleanup: wandbCleanup } =
    await createInstrumentedBus(session);

  try {
    const { findings, findingsPath, pocsPath } = await runTargetedPentestAgent({
      target,
      objectives,
      session,
      model,
      authConfig: buildAuthConfig(pensarConfig),
      eventBus: targetedBus,
    });

    console.log(`
${sep}
RESULTS
${sep}
Findings:  ${findings.length}
Path:      ${findingsPath}
POCs:      ${pocsPath}`);
  } finally {
    await wandbCleanup();
  }
}

async function runThreatModel() {
  const { config } = await import("dotenv");
  config();

  const { runThreatModelWorkflow } = await import("./core/api/threatModel");
  const { config: appConfig } = await import("./core/config");
  const { getDefaultModelForConfig } = await import("./core/providers/utils");
  const path = await import("path");
  type AIModel = import("./core/ai").AIModel;

  const pensarConfig = await appConfig.get();
  const dynamicDefault =
    getDefaultModelForConfig(pensarConfig)?.id ?? "claude-sonnet-4-5";
  const model = (getArg("--model") ?? dynamicDefault) as AIModel;

  const outputArg = getArg("--output") ?? getArg("-o") ?? "threat-model.md";
  const resolvedPath = path.isAbsolute(outputArg)
    ? outputArg
    : path.resolve(process.cwd(), outputArg);

  const sep = "=".repeat(60);
  console.log(`${sep}
THREAT MODEL GENERATION
${sep}
Codebase: ${process.cwd()}
Output:   ${resolvedPath}
Model:    ${model}
`);

  const threatBus = new AgentEventBus();
  threatBus.on("text-delta", (d) => process.stdout.write(d.text));
  threatBus.on("tool-call-complete", (d) => console.log(`\n  → ${d.toolName}`));
  threatBus.on("tool-result", (d) => console.log(`  ✓ ${d.toolName}`));
  threatBus.on("error", (d) => console.error("Error:", d.error));

  await runThreatModelWorkflow({
    codebasePath: process.cwd(),
    outputPath: resolvedPath,
    model,
    authConfig: buildAuthConfig(pensarConfig),
    eventBus: threatBus,
  });

  console.log(
    `\n${sep}\nCOMPLETE\n${sep}\nThreat model written to: ${resolvedPath}`,
  );
}

async function runUpgrade() {
  const currentVersion = getCurrentVersion();
  console.log(`Current version: v${currentVersion}\nChecking for updates...`);

  const result = await upgrade({ interactive: true });
  console.log(`\n${result.message}`);

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
} else if (command === "auth") {
  process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
  await import("./cli/auth");
} else if (command === "uninstall") {
  process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
  await import("./cli/uninstall");
} else if (command === "projects") {
  process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
  await import("./cli/projects");
} else if (command === "pentests") {
  process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
  await import("./cli/pentests");
} else if (command === "issues") {
  process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
  await import("./cli/issues");
} else if (command === "fixes") {
  process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
  await import("./cli/fixes");
} else if (command === "logs") {
  process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
  await import("./cli/logs");
} else if (command === "threat-model") {
  await runThreatModel();
} else if (command === "doctor") {
  const { runDoctor } = await import("./core/doctor");
  await runDoctor();
} else if (args.length === 0) {
  if (process.env.PENSAR_NO_TUI === "1") {
    console.error(
      "TUI mode requires Bun. Install Bun (https://bun.sh) or use a standalone binary release for interactive mode.",
    );
    console.error("All other commands work with Node — run 'pensar --help'.");
    process.exit(1);
  }
  await import("./tui/index.tsx");
} else {
  console.error(`Error: Unknown command '${command}'`);
  console.error();
  console.error("Run 'pensar --help' for usage information");
  process.exit(1);
}

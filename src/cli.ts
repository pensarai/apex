#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * Unified entry point for standalone binary compilation.
 * All modules are statically imported so Bun can bundle them.
 */

import { config as loadEnv } from "dotenv";
import packageJson from "../package.json";
import { type AIModel, buildAuthConfig } from "./core/ai";
import { setCurrentCommand } from "./core/api/clientIdentity";
import { resolveCliLogLevel } from "./core/cli/logLevelArgs";
import { resolvePentestMode } from "./core/cli/pentestMode";
import { AgentEventBus } from "./core/eventBus";
import { getCurrentVersion, upgrade } from "./core/installation";
import { logger } from "./core/logger";
import { startObservabilityRuntime } from "./core/observability/runtime";
import type { SessionInfo } from "./core/session";
import {
  combinePromptParts,
  resolveFlagValue,
  resolveThreatModelPrompt,
} from "./tui/utils/command-flags";

const args = process.argv.slice(2);
const version = packageJson.version;

loadEnv();

// Detect global --obfuscate flag and propagate to the TUI via env so the
// flag works regardless of where it appears in argv. The flag is stripped
// before any per-command parsing so it never collides with subcommand args.
const OBFUSCATE_FLAGS = new Set(["--obfuscate", "--redact", "-O"]);
const obfuscateRequested = args.some((a) => OBFUSCATE_FLAGS.has(a));
if (obfuscateRequested) {
  process.env.PENSAR_OBFUSCATE = "1";
  for (let i = args.length - 1; i >= 0; i--) {
    if (OBFUSCATE_FLAGS.has(args[i]!)) args.splice(i, 1);
  }
}

// Resolve diagnostic log level from CLI flags early, before any subsystem logs.
// (resolveCliLogLevel strips the flags from `args` in place.) Export
// PENSAR_LOG_LEVEL so child processes inherit the resolved level.
{
  const { level, invalid } = resolveCliLogLevel(args);
  if (invalid !== undefined) {
    // Always-visible (not gated by the log threshold): the flag was rejected.
    // We continue at the shorthand/default level rather than abort.
    console.error(
      `Ignoring invalid --log-level "${invalid}" (expected DEBUG|INFO|WARN|ERROR|SILENT)`,
    );
  }
  if (level) {
    logger.setLevel(level);
    process.env.PENSAR_LOG_LEVEL = level;
  }
}

// Resolve the subcommand AFTER global flags (--obfuscate, --log-level, etc.)
// are stripped, so `pensar --verbose pentest` still routes to `pentest`.
const command = args[0];

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
  const { attachWandbToEventBus } = await import(
    "./core/integrations/wandb/upload"
  );
  const wandbCleanup = await attachWandbToEventBus(session, bus).catch((e) => {
    console.warn("[wandb] Tracing disabled:", (e as Error).message);
    return null;
  });
  return { bus, cleanup: async () => wandbCleanup?.() };
}

// Returns the merged headers (global defaults < file < CLI flags), or
// `undefined` to let `sessions.create` snapshot the global defaults.
async function resolveCliHeaders(): Promise<
  Record<string, string> | undefined
> {
  const headerArgs = getAllArgs("--header");
  const headersFromArg = getArg("--headers-from");
  const noGlobal = hasFlag("--no-global-headers");

  if (headerArgs.length === 0 && !headersFromArg && !noGlobal) {
    return undefined;
  }

  const { parseHeaderLine, parseHeadersFromFile, formatParseError } =
    await import("./core/http/parse");
  const merged: Record<string, string> = {};

  if (!noGlobal) {
    const { config: appConfig } = await import("./core/config");
    const cfg = await appConfig.get();
    if (cfg.defaultHeaders) {
      Object.assign(merged, cfg.defaultHeaders);
    }
  }

  if (headersFromArg) {
    const parsed = await parseHeadersFromFile(headersFromArg);
    if (!parsed.ok) {
      for (const err of parsed.error) {
        console.error(`--headers-from error:\n${formatParseError(err)}`);
      }
      process.exit(1);
    }
    for (const entry of parsed.value) {
      merged[entry.name] = entry.value;
    }
  }

  for (const arg of headerArgs) {
    const parsed = parseHeaderLine(arg);
    if (!parsed.ok) {
      console.error(
        `--header "${arg}" rejected:\n${formatParseError(parsed.error)}`,
      );
      process.exit(1);
    }
    merged[parsed.value.name] = parsed.value.value;
  }

  return merged;
}

/**
 * Resolve the AI model from --model flag or configured provider default.
 * Errors clearly if no provider is configured instead of silently picking
 * a model that will fail at the API call level.
 */
async function resolveCliModel(): Promise<AIModel> {
  const explicit = getArg("--model");
  if (explicit) return explicit as AIModel;

  const { config: appConfig } = await import("./core/config");
  const { getDefaultModelForConfig } = await import("./core/providers/utils");
  const pensarConfig = await appConfig.get();
  const defaultModel = getDefaultModelForConfig(pensarConfig);

  if (!defaultModel) {
    console.error(
      "Error: No AI provider configured. Set one of:\n" +
        "  PENSAR_API_KEY     — Pensar Console (recommended)\n" +
        "  ANTHROPIC_API_KEY  — Anthropic direct\n" +
        "  OPENAI_API_KEY     — OpenAI\n" +
        "  OPENROUTER_API_KEY — OpenRouter\n" +
        "  CONCENTRATE_API_KEY — Concentrate\n" +
        "\nOr run 'pensar login' to connect to Pensar Console.",
    );
    process.exit(1);
  }

  return defaultModel.id as AIModel;
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function showHelp() {
  console.log(`Pensar - AI-Powered Penetration Testing CLI

Usage:
  pensar                             Launch the TUI
  pensar -p <prompt>                 Start an operator session with a prompt
  pensar pentest [options]            Run a full pentest orchestration
  pensar targeted-pentest [options]   Run a targeted pentest on a single target
  pensar threat-model [options]       Generate application-centric threat model
  pensar login                        Connect to Pensar Console
  pensar uninstall                    Uninstall Pensar (keeps sessions, memories, skills)
  pensar apps                         Manage the attack surface (apps & endpoints)
  pensar pentests                     List and manage pentests
  pensar targets                      List pentest targets and view their agent logs
  pensar issues                       List and manage security issues
  pensar fixes                        View security fixes
  pensar logs                         View agent execution logs
  pensar config headers               Manage global default HTTP headers
  pensar upgrade                      Update pensar to the latest version
  pensar doctor                       Check dependencies and install missing tools
  pensar help                         Show this help message
  pensar version                      Show version number

operator options (-p):
  -p, --prompt <text|@file>  (required) Prompt for the operator agent
  -s, --system <text|@file>  Override the default system prompt
  --target <url>             Target URL / domain / IP
  --model <model>            AI model (default: auto-selected from configured provider)
  --header "Name: Value"     Custom HTTP header (repeatable)
  --headers-from <file>      Load headers from a JSON object or Name:Value file
  --no-global-headers        Skip the global defaultHeaders snapshot

pentest options:
  --target <url>           (required) Target URL / domain / IP
  --cwd <path>             Source code path — enables whitebox attack surface
  --mode <mode>            Pentest mode: exfil (pivoting & flag extraction)
  --model <model>          AI model (default: auto-selected from configured provider)
  --extended-thinking       Enable extended thinking for supported models
  --task-driven             Enable task-driven architecture (experimental)
  --fast-strike            Single-operator fast strike: skip attack-surface/swarm
                           phases, one tight recon→exploit loop against the target
  --prompt <text|@file>    Guidance for the pentest agent (inline text or @filepath)
  --threat-model <text|@file>  Threat model to guide the pentest (inline or @filepath)
  --header "Name: Value"   Custom HTTP header (repeatable)
  --headers-from <file>    Load headers from a JSON object or Name:Value file
  --no-global-headers      Skip the global defaultHeaders snapshot

targeted-pentest options:
  --target <url>          (required) Target URL / domain / IP
  --objective <text>      (required, repeatable) Testing objective
  --model <model>         AI model (default: auto-selected from configured provider)
  --header "Name: Value"  Custom HTTP header (repeatable)
  --headers-from <file>   Load headers from a JSON object or Name:Value file
  --no-global-headers     Skip the global defaultHeaders snapshot

threat-model options:
  --output, -o <path>  Output file path (default: ./threat-model.md)
  --model <model>      AI model (default: auto-selected from configured provider)

Global options:
  -h, --help         Show this help message
  -v, --version      Show version number
  --log-level <lvl>  Diagnostic log level: debug|info|warn|error|silent
  --verbose          Shorthand for --log-level debug
  --quiet            Shorthand for --log-level warn
  --obfuscate        Run the TUI in obfuscation mode — redacts hostnames,
                     IPs, UUIDs, emails, paths, tokens, and apparent
                     company names so screenshots are safe to share.
`);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function runPentest() {
  const { runPentestAgent } = await import("./core/api/blackboxPentest");
  const { sessions } = await import("./core/session");
  const { config: appConfig } = await import("./core/config");

  const target = getArgRequired("--target");
  const cwd = getArg("--cwd");
  const mode = getArg("--mode");
  const promptRaw = getArg("--prompt");
  const threatModelRaw = getArg("--threat-model");
  const enableThinking = hasFlag("--extended-thinking");
  const taskDriven = hasFlag("--task-driven");
  const fastStrike = hasFlag("--fast-strike");

  // Resolve and combine threat model + prompt
  const resolvedTm = threatModelRaw
    ? resolveThreatModelPrompt(threatModelRaw)
    : undefined;
  const resolvedPrompt = promptRaw ? resolveFlagValue(promptRaw) : undefined;
  const prompt = combinePromptParts(resolvedTm, resolvedPrompt);

  const pensarConfig = await appConfig.get();
  const model = await resolveCliModel();
  const headers = await resolveCliHeaders();
  const { exfilMode, warning: modeWarning } = resolvePentestMode(mode);

  if (modeWarning) {
    console.warn(modeWarning);
  }

  if (taskDriven && fastStrike) {
    console.warn(
      "Warning: --task-driven has no effect with --fast-strike (task tools are excluded).",
    );
  }

  const sep = "=".repeat(60);
  console.log(`${sep}
PENTEST ORCHESTRATION
${sep}
Target:  ${target}${cwd ? `\nCwd:     ${cwd} (whitebox)` : ""}${exfilMode ? "\nMode:    exfil" : ""}
Model:   ${model}${enableThinking ? "\nThinking: enabled" : ""}${taskDriven ? "\nTask-driven: enabled" : ""}${fastStrike ? "\nFast strike: enabled" : ""}${headers ? `\nHeaders: ${Object.keys(headers).length} configured` : ""}
`);

  const session = await sessions.create({
    name: cwd ? "Whitebox Pentest" : "Blackbox Pentest",
    targets: [target],
    config: {
      ...(cwd ? { codebasePath: cwd } : {}),
      ...(exfilMode ? { exfilMode: true } : {}),
      ...(prompt ? { prompt } : {}),
      ...(taskDriven ? { taskDriven: true } : {}),
      ...(headers !== undefined ? { headers } : {}),
    },
  });
  console.log(`PENSAR_SESSION_PATH:${session.rootPath}`);

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
        ...(fastStrike ? { fastStrike: true } : {}),
        surfaceIntegrationEnabled: pensarConfig.surfaceIntegrationEnabled,
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
  const { runTargetedPentestAgent } = await import(
    "./core/api/targetedPentest"
  );
  const { sessions } = await import("./core/session");
  const { config: appConfig } = await import("./core/config");

  const target = getArgRequired("--target");
  const objectives = getAllArgs("--objective");

  const pensarConfig = await appConfig.get();
  const model = await resolveCliModel();

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

  const headers = await resolveCliHeaders();
  const session = await sessions.create({
    name: "Targeted Pentest",
    targets: [target],
    ...(headers !== undefined ? { config: { headers } } : {}),
  });
  console.log(`PENSAR_SESSION_PATH:${session.rootPath}`);

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
  const { runThreatModelWorkflow } = await import("./core/api/threatModel");
  const { config: appConfig } = await import("./core/config");
  const path = await import("node:path");

  const pensarConfig = await appConfig.get();
  const model = await resolveCliModel();

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

async function runOperator() {
  const { runOffensiveSecurityAgent } = await import("./core/api/offesecAgent");
  const { sessions, normalizeMessages, getResumeMessages } = await import(
    "./core/session"
  );
  const { ALL_TOOL_NAMES, SKILL_TOOL_NAMES } = await import(
    "./core/agents/offSecAgent"
  );
  const { config: appConfig } = await import("./core/config");
  const { createInterface } = await import("node:readline");
  const { readFileSync, existsSync } = await import("node:fs");
  const path = await import("node:path");
  const { stepCountIs } = await import("ai");
  type ModelMessage = import("ai").ModelMessage;

  const promptRaw = getArg("-p") ?? getArg("--prompt");
  if (!promptRaw) {
    console.error("Error: -p <prompt> is required");
    process.exit(1);
  }

  const prompt = resolveFlagValue(promptRaw);
  const systemRaw = getArg("-s") ?? getArg("--system");
  const systemPrompt = systemRaw ? resolveFlagValue(systemRaw) : undefined;
  const target = getArg("--target");
  const pensarConfig = await appConfig.get();
  const model = await resolveCliModel();

  const sep = "─".repeat(60);
  console.log(`${sep}
OPERATOR SESSION
${sep}
Model:   ${model}${target ? `\nTarget:  ${target}` : ""}
${sep}\n`);

  const headers = await resolveCliHeaders();
  const session = await sessions.create({
    name: "Operator Session",
    targets: target ? [target] : [],
    config: {
      mode: "operator",
      agentCwd: process.cwd(),
      operatorSettings: {
        initialMode: "auto",
        requireApproval: false,
        enableSuggestions: false,
      },
      ...(headers !== undefined ? { headers } : {}),
    },
  });

  const { bus, cleanup: wandbCleanup } = await createInstrumentedBus(session);

  let currentPrompt = prompt;
  let messages: ModelMessage[] | undefined;

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const askFollowUp = (): Promise<string | null> =>
    new Promise((resolve) => {
      process.stdout.write(`\n${sep}\n`);
      rl.question("follow-up (empty to exit): ", (answer) => {
        const trimmed = answer.trim();
        resolve(trimmed || null);
      });
    });

  try {
    for (;;) {
      await runOffensiveSecurityAgent({
        prompt: currentPrompt,
        ...(systemPrompt ? { system: systemPrompt } : {}),
        model,
        target,
        activeTools: [...ALL_TOOL_NAMES, ...SKILL_TOOL_NAMES] as string[],
        stopWhen: stepCountIs(10000),
        authConfig: buildAuthConfig(pensarConfig),
        eventBus: bus,
        session,
        messages,
      });

      // Read back persisted messages for the next turn
      const messagesPath = path.join(session.rootPath, "messages.json");
      if (existsSync(messagesPath)) {
        const raw = JSON.parse(readFileSync(messagesPath, "utf-8"));
        const allMessages: ModelMessage[] = Array.isArray(raw) ? raw : [];
        messages = normalizeMessages(getResumeMessages(allMessages));
      }

      const followUp = await askFollowUp();
      if (!followUp) break;
      currentPrompt = followUp;
      // Append the follow-up as a user message so the conversation
      // ends with a user turn (required by Anthropic models).
      messages = normalizeMessages([
        ...(messages ?? []),
        { role: "user" as const, content: followUp },
      ]);
    }
  } finally {
    rl.close();
    await wandbCleanup();
  }

  console.log(`\nSession: ${session.rootPath}`);
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

// Standalone CLI entrypoint: own the optional OTel runtime. No-op unless an
// OTLP endpoint is configured; the TUI branch below takes over the process
// and manages the runtime's lifecycle in its own exit path.
const observabilityRuntime = startObservabilityRuntime();

// Tell Console which command is talking to it; one place, so a command added
// below is covered without another edit.
setCurrentCommand(command);

try {
  if (hasFlag("-p") || command === "--prompt") {
    await runOperator();
  } else if (
    command === "version" ||
    command === "--version" ||
    command === "-v"
  ) {
    console.log(`v${version}`);
  } else if (command === "help" || command === "--help" || command === "-h") {
    showHelp();
  } else if (command === "upgrade" || command === "update") {
    await runUpgrade();
  } else if (command === "pentest") {
    await runPentest();
  } else if (command === "targeted-pentest") {
    await runTargetedPentest();
  } else if (command === "login" || command === "auth") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/auth");
  } else if (command === "uninstall") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/uninstall");
  } else if (command === "apps") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/apps");
  } else if (command === "pentests") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/pentests");
  } else if (command === "targets") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/targets");
  } else if (command === "issues") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/issues");
  } else if (command === "fixes") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/fixes");
  } else if (command === "logs") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/logs");
  } else if (command === "config") {
    process.argv = [process.argv[0], process.argv[1], ...args.slice(1)];
    await import("./cli/config");
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
} finally {
  // Preserve command failures while still making process-boundary flushing
  // best-effort. The TUI owns its runtime lifecycle after import.
  if (args.length !== 0) {
    await observabilityRuntime.shutdown().catch(() => {});
  }
}

// Some pentest tool subsystems can leave handles open after completion. Keep
// the explicit exit, but only after the final OTLP batch has been flushed.
if (command === "pentest" || command === "targeted-pentest") {
  process.exit(0);
}

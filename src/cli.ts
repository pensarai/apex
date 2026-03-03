#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * Unified entry point for standalone binary compilation.
 * All modules are statically imported so Bun can bundle them.
 */

import packageJson from "../package.json";
import { getCurrentVersion, upgrade } from "./core/installation";

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
    "  pensar threat-model [options]       Run an application-centric threat model",
  );
  console.log(
    "  pensar knowledge [subcommand]      Manage the attack knowledge base",
  );
  console.log(
    "  pensar upgrade                      Update pensar to the latest version",
  );
  console.log(
    "  pensar doctor                       Check dependencies and install missing tools",
  );
  console.log("  pensar help                         Show this help message");
  console.log("  pensar version                      Show version number");
  console.log();
  console.log("pentest options:");
  console.log("  --target <url>     (required) Target URL / domain / IP");
  console.log(
    "  --cwd <path>       Source code path — enables whitebox attack surface",
  );
  console.log(
    "  --mode <mode>      Pentest mode: exfil (pivoting & flag extraction)",
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
  console.log("threat-model options:");
  console.log(
    "  --cwd <path>            Local codebase path for whitebox analysis",
  );
  console.log(
    "  --target <url>          Target URL for blackbox analysis",
  );
  console.log(
    "  --model <model>         AI model (default: claude-sonnet-4-5)",
  );
  console.log(
    "                          (at least one of --cwd or --target is required)",
  );
  console.log();
  console.log("knowledge subcommands:");
  console.log("  pensar knowledge list [--category X]   List techniques");
  console.log("  pensar knowledge add <file.json>       Add a technique");
  console.log(
    "  pensar knowledge search <query>        Search the knowledge base",
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
  const { config } = await import("dotenv");
  config();

  const { runPentestAgent } = await import("./core/api/blackboxPentest");
  const { sessions } = await import("./core/session");
  const { config: appConfig } = await import("./core/config");
  type AIModel = import("./core/ai").AIModel;

  const target = getArgRequired("--target");
  const cwd = getArg("--cwd");
  const mode = getArg("--mode");
  const model = (getArg("--model") ?? "claude-sonnet-4-5") as AIModel;
  const exfilMode = mode === "exfil";

  console.log("=".repeat(60));
  console.log("PENTEST ORCHESTRATION");
  console.log("=".repeat(60));
  console.log(`Target:  ${target}`);
  if (cwd) console.log(`Cwd:     ${cwd} (whitebox)`);
  if (exfilMode) console.log(`Mode:    exfil`);
  console.log(`Model:   ${model}`);
  console.log();

  const pensarConfig = await appConfig.get();

  const session = await sessions.create({
    name: cwd ? "Whitebox Pentest" : "Blackbox Pentest",
    targets: [target],
    config: {
      ...(cwd ? { cwd } : {}),
      ...(exfilMode ? { exfilMode: true } : {}),
    },
  });

  const run = runPentestAgent({
    target,
    ...(cwd ? { cwd } : {}),
    session,
    model,
    authConfig: {
      anthropicAPIKey: pensarConfig.anthropicAPIKey ?? undefined,
      openAiAPIKey: pensarConfig.openAiAPIKey ?? undefined,
      openRouterAPIKey: pensarConfig.openRouterAPIKey ?? undefined,
      bedrock: {
        apiKey: pensarConfig.bedrockAPIKey ?? undefined,
        accessKeyId: pensarConfig.bedrockAccessKeyId ?? undefined,
        secretAccessKey: pensarConfig.bedrockSecretAccessKey ?? undefined,
        sessionToken: pensarConfig.bedrockSessionToken ?? undefined,
        region: pensarConfig.bedrockRegion ?? undefined,
      },
      local: pensarConfig.localModelUrl
        ? { baseURL: pensarConfig.localModelUrl }
        : undefined,
    },
  });

  for await (const event of run) {
    switch (event.type) {
      case "text-delta":
        process.stdout.write(event.data.text);
        break;
      case "tool-call":
        console.log(`\n→ ${event.data.toolName}`);
        break;
      case "tool-result":
        console.log(`✓ ${event.data.toolName} completed`);
        break;
      case "error":
        console.error("Error:", event.error);
        break;
    }
  }

  const { findings, findingsPath, pocsPath, reportPath } = await run.result;

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
  const { config } = await import("dotenv");
  config();

  const { runTargetedPentestAgent } =
    await import("./core/api/targetedPentest");
  const { sessions } = await import("./core/session");
  const { config: appConfig } = await import("./core/config");
  type AIModel = import("./core/ai").AIModel;

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

  const pensarConfig = await appConfig.get();

  const session = await sessions.create({
    name: "Targeted Pentest",
    targets: [target],
  });

  const run = runTargetedPentestAgent({
    target,
    objectives,
    session,
    model,
    authConfig: {
      anthropicAPIKey: pensarConfig.anthropicAPIKey ?? undefined,
      openAiAPIKey: pensarConfig.openAiAPIKey ?? undefined,
      openRouterAPIKey: pensarConfig.openRouterAPIKey ?? undefined,
      bedrock: {
        apiKey: pensarConfig.bedrockAPIKey ?? undefined,
        accessKeyId: pensarConfig.bedrockAccessKeyId ?? undefined,
        secretAccessKey: pensarConfig.bedrockSecretAccessKey ?? undefined,
        sessionToken: pensarConfig.bedrockSessionToken ?? undefined,
        region: pensarConfig.bedrockRegion ?? undefined,
      },
      local: pensarConfig.localModelUrl
        ? { baseURL: pensarConfig.localModelUrl }
        : undefined,
    },
  });

  for await (const event of run) {
    switch (event.type) {
      case "text-delta":
        process.stdout.write(event.data.text);
        break;
      case "tool-call":
        console.log(`\n→ ${event.data.toolName}`);
        break;
      case "tool-result":
        console.log(`✓ ${event.data.toolName} completed`);
        break;
      case "error":
        console.error("Error:", event.error);
        break;
    }
  }

  const { findings, findingsPath, pocsPath } = await run.result;

  console.log();
  console.log("=".repeat(60));
  console.log("RESULTS");
  console.log("=".repeat(60));
  console.log(`Findings:  ${findings.length}`);
  console.log(`Path:      ${findingsPath}`);
  console.log(`POCs:      ${pocsPath}`);
}

async function runThreatModel() {
  const { config } = await import("dotenv");
  config();

  const { runThreatModelAgent } = await import("./core/api/threatModel");
  const { sessions } = await import("./core/session");
  const { config: appConfig } = await import("./core/config");
  type AIModel = import("./core/ai").AIModel;

  const cwd = getArg("--cwd");
  const target = getArg("--target");
  const model = (getArg("--model") ?? "claude-sonnet-4-5") as AIModel;

  if (!cwd && !target) {
    console.error("Error: at least one of --cwd or --target is required");
    process.exit(1);
  }

  const mode = cwd ? "whitebox" : "blackbox";

  console.log("=".repeat(60));
  console.log("THREAT MODEL");
  console.log("=".repeat(60));
  console.log(`Mode:     ${mode}`);
  if (cwd) console.log(`Codebase: ${cwd}`);
  if (target) console.log(`Target:   ${target}`);
  console.log(`Model:    ${model}`);
  console.log();

  const pensarConfig = await appConfig.get();

  const session = await sessions.create({
    name: `Threat Model (${mode})`,
    targets: [cwd ?? target!],
  });

  const run = runThreatModelAgent({
    ...(cwd ? { cwd } : {}),
    ...(target ? { target } : {}),
    session,
    model,
    authConfig: {
      anthropicAPIKey: pensarConfig.anthropicAPIKey ?? undefined,
      openAiAPIKey: pensarConfig.openAiAPIKey ?? undefined,
      openRouterAPIKey: pensarConfig.openRouterAPIKey ?? undefined,
      bedrock: {
        apiKey: pensarConfig.bedrockAPIKey ?? undefined,
        accessKeyId: pensarConfig.bedrockAccessKeyId ?? undefined,
        secretAccessKey: pensarConfig.bedrockSecretAccessKey ?? undefined,
        sessionToken: pensarConfig.bedrockSessionToken ?? undefined,
        region: pensarConfig.bedrockRegion ?? undefined,
      },
      local: pensarConfig.localModelUrl
        ? { baseURL: pensarConfig.localModelUrl }
        : undefined,
    },
  });

  for await (const event of run) {
    switch (event.type) {
      case "text-delta":
        process.stdout.write(event.data.text);
        break;
      case "tool-call":
        console.log(`\n→ ${event.data.toolName}`);
        break;
      case "tool-result":
        console.log(`✓ ${event.data.toolName} completed`);
        break;
      case "subagent-spawn":
        console.log(`\n▸ Phase: ${event.subagentId}`);
        break;
      case "subagent-complete":
        console.log(`✓ Phase: ${event.subagentId} ${event.status}`);
        break;
      case "error":
        console.error("Error:", event.error);
        break;
    }
  }

  const result = await run.result;

  console.log();
  console.log("=".repeat(60));
  console.log("RESULTS");
  console.log("=".repeat(60));
  console.log(`Attack Paths: ${result.summary.totalAttackPaths}`);
  console.log(`  Critical: ${result.summary.bySeverity.critical}`);
  console.log(`  High:     ${result.summary.bySeverity.high}`);
  console.log(`  Medium:   ${result.summary.bySeverity.medium}`);
  console.log(`  Low:      ${result.summary.bySeverity.low}`);
  console.log();
  console.log(`Markdown: ${result.files.markdownPath}`);
  console.log(`JSON:     ${result.files.jsonPath}`);
}

async function runKnowledge() {
  const subcommand = args[1];
  const subArgs = args.slice(2);

  const {
    getAttackKnowledgeStore,
  } = await import("./core/knowledge/attackKnowledge");
  const { getQueryEngine } = await import("./core/knowledge/queryEngine");

  const store = getAttackKnowledgeStore();
  const engine = getQueryEngine();

  if (subcommand === "list") {
    const category = getArg("--category", subArgs);
    const techniques = category
      ? engine.listByCategory(category as any)
      : store.getAll();

    if (techniques.length === 0) {
      console.log("No techniques found.");
      return;
    }

    console.log(`Attack Knowledge Base (${techniques.length} techniques)\n`);
    for (const t of techniques) {
      console.log(
        `  [${t.category}] ${t.id}`,
      );
      console.log(`    ${t.title}`);
      console.log(`    Tags: ${t.tags.join(", ")}`);
      console.log();
    }
  } else if (subcommand === "add") {
    const filePath = subArgs[0];
    if (!filePath) {
      console.error("Error: file path is required");
      console.error("Usage: pensar knowledge add <file.json>");
      process.exit(1);
    }

    const { readFileSync } = await import("fs");
    try {
      const raw = readFileSync(filePath, "utf-8");
      const technique = JSON.parse(raw);

      if (!technique.id || !technique.title || !technique.category) {
        console.error(
          "Error: technique must have at least id, title, and category fields",
        );
        process.exit(1);
      }

      store.addTechnique(technique);
      console.log(`Added technique: ${technique.id} — ${technique.title}`);
    } catch (err: any) {
      console.error(`Error reading/parsing file: ${err.message}`);
      process.exit(1);
    }
  } else if (subcommand === "search") {
    const query = subArgs.join(" ");
    if (!query) {
      console.error("Error: search query is required");
      console.error("Usage: pensar knowledge search <query>");
      process.exit(1);
    }

    const results = engine.query({ freeText: query, limit: 10 });

    if (results.length === 0) {
      console.log("No matching techniques found.");
      return;
    }

    console.log(`Search results for "${query}" (${results.length} matches)\n`);
    for (const r of results) {
      console.log(`  [${r.technique.category}] ${r.technique.title}`);
      console.log(`    ${r.technique.technique.summary.substring(0, 120)}...`);
      console.log(`    Tags: ${r.technique.tags.join(", ")}`);
      console.log(`    File: ${r.filePath}`);
      console.log();
    }
  } else {
    console.log("Usage:");
    console.log("  pensar knowledge list [--category X]   List techniques");
    console.log("  pensar knowledge add <file.json>       Add a technique");
    console.log(
      "  pensar knowledge search <query>        Search the knowledge base",
    );
  }
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
} else if (command === "threat-model") {
  await runThreatModel();
} else if (command === "knowledge") {
  await runKnowledge();
} else if (command === "doctor") {
  const { runDoctor } = await import("./core/doctor");
  await runDoctor();
} else if (args.length === 0) {
  await import("./tui/index.tsx");
} else {
  console.error(`Error: Unknown command '${command}'`);
  console.error();
  console.error("Run 'pensar --help' for usage information");
  process.exit(1);
}

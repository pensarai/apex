import type { CommandDefinition } from "./command-router";
import type { Route, WebCommandOptions } from "./context/route";
import {
  parseWebFlags,
  hasEnoughFlagsToSkipWizard,
  combinePromptParts,
} from "./utils/command-flags";
import { getAllThemeNames } from "./theme";
import { config } from "../core/config";
/**
 * Define your application's CommandContext type with specific methods
 */
export interface AppCommandContext {
  route: Route;
  navigate: (route: Route) => void;
  openSessionsDialog?: () => void;
  openThemeDialog?: () => void;
  openModelDialog?: () => void;
  openProvidersDialog?: () => void;
  openCreditsDialog?: () => void;
  openHelpDialog?: () => void;
  openAuthDialog?: () => void;
  openPentestDialog?: (flags?: WebCommandOptions) => void;
  openSkillsDialog?: (slug?: string) => void;
}

/**
 * Command option definition for help text and autocomplete
 */
export interface CommandOption {
  name: string;
  description: string;
  valueHint?: string; // e.g., "<url>" for --target <url>
}

/**
 * Command category type and display order.
 */
export type CommandCategory = "Pentesting" | "Configuration" | "General";

export const categories: CommandCategory[] = [
  "Pentesting",
  "Configuration",
  "General",
];

/**
 * Command configuration object - easy to map over and export
 */
export interface CommandConfig {
  name: string;
  aliases?: string[];
  description?: string;
  category?: CommandCategory;
  options?: CommandOption[];
  /** If true, command works but doesn't appear in the autocomplete menu or help dialog */
  hidden?: boolean;
  handler: (args: string[], ctx: AppCommandContext) => void | Promise<void>;
}

/**
 * All available commands.
 * Array order = display order in autocomplete dropdown and help dialog.
 */
export const commands: CommandConfig[] = [
  // — Pentesting —
  {
    name: "pentest",
    aliases: ["p", "web", "w"],
    description: "Start autonomous pentest swarm",
    category: "Pentesting",
    options: [
      {
        name: "--target",
        valueHint: "<url>",
        description: "Target URL to test",
      },
      { name: "--name", valueHint: "<name>", description: "Session name" },
      {
        name: "--tier",
        valueHint: "<1-5>",
        description: "Auto-approve permission tier",
      },
      { name: "--auth-url", valueHint: "<url>", description: "Login page URL" },
      {
        name: "--auth-user",
        valueHint: "<user>",
        description: "Auth username",
      },
      {
        name: "--auth-pass",
        valueHint: "<pass>",
        description: "Auth password",
      },
      {
        name: "--auth-instructions",
        valueHint: "<text>",
        description: "Auth instructions",
      },
      {
        name: "--hosts",
        valueHint: "<h1,h2,...>",
        description: "Allowed hosts",
      },
      {
        name: "--ports",
        valueHint: "<p1,p2,...>",
        description: "Allowed ports",
      },
      { name: "--strict", description: "Enable strict scope mode" },
      {
        name: "--headers",
        valueHint: "<none|default|custom>",
        description: "Headers mode",
      },
      {
        name: "--header",
        valueHint: "<Name:Value>",
        description: "Custom header (repeatable)",
      },
      { name: "--model", valueHint: "<model>", description: "AI model to use" },
      {
        name: "--prompt",
        valueHint: "<text|@file>",
        description: "Guidance for the pentest agent",
      },
      {
        name: "--threat-model",
        valueHint: "<text|@file>",
        description: "Threat model to guide the pentest (inline or @filepath)",
      },
    ],
    handler: async (args, ctx) => {
      const flags = parseWebFlags(args);

      if (flags.target && hasEnoughFlagsToSkipWizard(flags)) {
        const skillArgs: Record<string, string> = {};
        if (flags.target) skillArgs.target = flags.target;
        if (flags.authUrl) skillArgs["auth-url"] = flags.authUrl;
        if (flags.authUser) skillArgs["auth-user"] = flags.authUser;
        if (flags.authPass) skillArgs["auth-pass"] = flags.authPass;
        if (flags.authInstructions)
          skillArgs["auth-instructions"] = flags.authInstructions;
        if (flags.hosts?.length) skillArgs.hosts = flags.hosts.join(",");
        if (flags.ports?.length)
          skillArgs.ports = flags.ports.map(String).join(",");
        if (flags.strict) skillArgs.strict = "true";
        const combinedPrompt = combinePromptParts(
          flags.threatModel,
          flags.prompt,
        );
        if (combinedPrompt) skillArgs.prompt = combinedPrompt;

        ctx.navigate({
          type: "operator",
          nonce: Date.now(),
          initialConfig: {
            requireApproval: false,
            target: flags.target,
            sandbox: true,
          },
          initialSkill: { slug: "pentest", args: skillArgs },
        });
        return;
      }
      // Open WebWizard dialog for target input
      ctx.openPentestDialog?.({ auto: true, ...flags });
    },
  },
  {
    name: "operator",
    aliases: ["o"],
    description: "Start interactive operator session",
    category: "Pentesting",
    options: [
      {
        name: "--target",
        valueHint: "<url>",
        description: "Target URL to test",
      },
      { name: "--name", valueHint: "<name>", description: "Session name" },
      {
        name: "--autopilot",
        description: "Disable approval gates (auto-approve all actions)",
      },
      {
        name: "--mode",
        valueHint: "<plan|manual|auto>",
        description: "Operator mode",
      },
      { name: "--auth-url", valueHint: "<url>", description: "Login page URL" },
      {
        name: "--auth-user",
        valueHint: "<user>",
        description: "Auth username",
      },
      {
        name: "--auth-pass",
        valueHint: "<pass>",
        description: "Auth password",
      },
      {
        name: "--auth-instructions",
        valueHint: "<text>",
        description: "Auth instructions",
      },
      {
        name: "--hosts",
        valueHint: "<h1,h2,...>",
        description: "Allowed hosts",
      },
      {
        name: "--ports",
        valueHint: "<p1,p2,...>",
        description: "Allowed ports",
      },
      { name: "--strict", description: "Enable strict scope mode" },
      {
        name: "--headers",
        valueHint: "<none|default|custom>",
        description: "Headers mode",
      },
      {
        name: "--header",
        valueHint: "<Name:Value>",
        description: "Custom header (repeatable)",
      },
      { name: "--model", valueHint: "<model>", description: "AI model to use" },
      {
        name: "--sandbox",
        description: "Use isolated session directory as working directory",
      },
      {
        name: "--task-driven",
        description: "Structured task tracking (experimental)",
      },
    ],
    handler: async (args, ctx) => {
      const flags = parseWebFlags(args);
      ctx.navigate({
        type: "operator",
        nonce: Date.now(),
        initialConfig: {
          requireApproval: flags.requireApproval ?? true,
          target: flags.target,
          sandbox: flags.sandbox,
          taskDriven: flags.taskDriven,
        },
      });
    },
  },
  {
    name: "plan",
    description: "Show current pentest plan",
    category: "Pentesting",
    handler: async () => {
      // Handled by the operator dashboard — this is a no-op for routing
    },
  },
  {
    name: "threat-model",
    aliases: ["tm"],
    description: "Generate application-centric threat model",
    category: "Pentesting",
    options: [
      {
        name: "--output",
        valueHint: "<path>",
        description: "Output file path (default: ./threat-model.md)",
      },
      {
        name: "--model",
        valueHint: "<model>",
        description: "AI model to use",
      },
    ],
    handler: async (args, ctx) => {
      let outputPath = "threat-model.md";
      let model: string | undefined;
      for (let i = 0; i < args.length; i++) {
        if ((args[i] === "--output" || args[i] === "-o") && args[i + 1]) {
          outputPath = args[i + 1];
        } else if (args[i] === "--model" && args[i + 1]) {
          model = args[i + 1];
        }
      }

      const skillArgs: Record<string, string> = { output: outputPath };
      if (model) skillArgs.model = model;

      ctx.navigate({
        type: "operator",
        nonce: Date.now(),
        initialConfig: {
          requireApproval: true,
        },
        initialSkill: {
          slug: "threat-model",
          args: skillArgs,
        },
      });
    },
  },
  {
    name: "resume",
    aliases: ["sessions", "s"],
    description: "Resume a previous session",
    category: "Pentesting",
    handler: async (_args, ctx) => {
      ctx.openSessionsDialog?.();
    },
  },
  {
    name: "new",
    description: "Start a new operator session",
    category: "Pentesting",
    handler: async (args, ctx) => {
      ctx.navigate({ type: "operator", nonce: Date.now() });
    },
  },

  // — Configuration —
  {
    name: "auth",
    description: "Connect to Pensar Console for managed inference",
    category: "Configuration",
    handler: async (args, ctx) => {
      ctx.openAuthDialog?.();
    },
  },
  {
    name: "credits",
    aliases: ["buy"],
    description: "Buy credits / check balance",
    category: "Configuration",
    handler: async (args, ctx) => {
      ctx.openCreditsDialog?.();
    },
  },
  {
    name: "models",
    description: "Show available AI models",
    category: "Configuration",
    handler: async (args, ctx) => {
      ctx.openModelDialog?.();
    },
  },
  {
    name: "providers",
    description: "Manage AI providers and API keys",
    category: "Configuration",
    handler: async (args, ctx) => {
      ctx.openProvidersDialog?.();
    },
  },
  {
    name: "themes",
    aliases: ["theme"],
    description: "Manage application themes",
    category: "Configuration",
    options: [
      {
        name: "<name>",
        description: "Switch directly to a named theme",
      },
      {
        name: "mode",
        description: "Toggle or set dark/light mode (dark|light|auto)",
      },
    ],
    handler: async (args, ctx) => {
      // /theme mode [dark|light|auto] — mode subcommand
      if (args[0] === "mode") {
        const modeArg = args[1];
        if (modeArg === "dark" || modeArg === "light") {
          await config.update({ themeMode: modeArg });
        } else if (modeArg === "auto") {
          await config.update({ themeMode: "auto" });
        } else {
          // Toggle — actual toggling happens in the ThemeProvider (caller reads config)
          const current = await config.get();
          const newMode = current.themeMode === "light" ? "dark" : "light";
          await config.update({ themeMode: newMode });
        }
        return;
      }

      // /theme <name> — direct theme switch
      if (args[0]) {
        const name = args[0].toLowerCase();
        const allThemes = getAllThemeNames();
        const match = allThemes.find((t) => t === name);
        if (match) {
          await config.update({ theme: match });
        }
        return;
      }

      // /theme — open picker
      ctx.openThemeDialog?.();
    },
  },

  // — General —
  {
    name: "skills",
    description: "View installed skills",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openSkillsDialog?.(args[0]);
    },
  },
  {
    name: "help",
    description: "Show help dialog",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openHelpDialog?.();
    },
  },
  {
    name: "exit",
    aliases: ["quit", "q"],
    description: "Exit the application",
    category: "General",
    handler: async () => {
      process.kill(process.pid, "SIGINT");
    },
  },

  // — Hidden (functional but not shown in autocomplete/help) —
  {
    name: "tools",
    aliases: ["t"],
    description: "View and manage active tools (session only)",
    category: "General",
    hidden: true,
    handler: async (args, ctx) => {
      // This command is handled by the session view when in a session
      // From home, it does nothing - tools panel only works in session context
      if (ctx.route.type !== "operator") {
        return;
      }
    },
  },
];

/**
 * Convert command configs to command definitions for the router
 * This allows the router to properly bind context
 */
export const commandRegistry: CommandDefinition<AppCommandContext>[] =
  commands.map((config) => (ctx) => ({
    name: config.name,
    aliases: config.aliases,
    description: config.description,
    handler: async (args) => {
      await config.handler(args, ctx);
    },
  }));

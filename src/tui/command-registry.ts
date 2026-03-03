import type { CommandDefinition } from "./command-router";
import type { Route } from "./context/route";
import {
  parseWebFlags,
  hasEnoughFlagsToSkipWizard,
  createOperatorSessionFromFlags,
  createSwarmSessionFromFlags,
} from "./utils/command-flags";
import { getAllThemeNames } from "./theme";
import { config } from "../core/config";
/**
 * Define your application's CommandContext type with specific methods
 */
export interface AppCommandContext {
  route: Route;
  navigate: (route: Route) => void;
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
 * Command configuration object - easy to map over and export
 */
export interface CommandConfig {
  name: string;
  aliases?: string[];
  description?: string;
  category?: string;
  options?: CommandOption[];
  /** If true, command works but doesn't appear in the autocomplete menu */
  hidden?: boolean;
  handler: (args: string[], ctx: AppCommandContext) => void | Promise<void>;
}

/**
 * All available commands in a simple, mappable array
 */
export const commands: CommandConfig[] = [
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
    ],
    handler: async (args, ctx) => {
      const flags = parseWebFlags(args);

      // Pentest command always uses swarm mode
      if (flags.target && hasEnoughFlagsToSkipWizard(flags)) {
        try {
          const session = await createSwarmSessionFromFlags(flags);
          ctx.navigate({ type: "pentest", sessionId: session.id });
          return;
        } catch (e) {
          // Fall through to wizard on error
          console.error("Failed to create session:", e);
        }
      }
      // Navigate to WebWizard (swarm wizard) for target input
      ctx.navigate({
        type: "base",
        path: "web",
        options: { auto: true, ...flags },
      });
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
        name: "--mode",
        valueHint: "<plan|manual|auto>",
        description: "Operator mode",
      },
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
    ],
    handler: async (args, ctx) => {
      const flags = parseWebFlags(args);

      // Operator mode - interactive session with human guidance
      if (flags.target && hasEnoughFlagsToSkipWizard(flags)) {
        try {
          const session = await createOperatorSessionFromFlags(flags);
          ctx.navigate({ type: "pentest", sessionId: session.id });
          return;
        } catch (e) {
          // Fall through to wizard on error
          console.error("Failed to create session:", e);
        }
      }
      // Navigate to operator wizard with pre-filled values
      ctx.navigate({
        type: "base",
        path: "operator",
        options: flags as Record<string, unknown>,
      });
    },
  },
  {
    name: "help",
    description: "Show help dialog",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "help",
      });
    },
  },
  {
    name: "config",
    description: "Show config dialog",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "config",
      });
    },
  },
  {
    name: "models",
    description: "Show available AI models",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "models",
      });
    },
  },
  {
    name: "providers",
    description: "Manage AI providers and API keys",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "providers",
      });
    },
  },
  {
    name: "sessions",
    aliases: ["s"],
    description: "Browse previous sessions",
    category: "Pentesting",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "sessions",
      });
    },
  },
  {
    name: "chat",
    aliases: ["c"],
    description: "Open the Chat TUI interface",
    category: "General",
    hidden: true,
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "home",
      });
    },
  },
  {
    name: "themes",
    aliases: ["theme"],
    description: "Manage application themes",
    category: "General",
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
      ctx.navigate({ type: "base", path: "theme" });
    },
  },
  {
    name: "tools",
    aliases: ["t"],
    description: "View and manage active tools (session only)",
    category: "Session",
    hidden: true,
    handler: async (args, ctx) => {
      // This command is handled by the session view when in a session
      // From home, it does nothing - tools panel only works in session context
      if (ctx.route.type !== "pentest") {
        // Not in a session - command is a no-op
        return;
      }
      // The session view will detect this command via route options
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
  {
    name: "auth",
    description: "Connect to Pensar Console for managed inference",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "auth",
      });
    },
  },

  {
    name: "credits",
    aliases: ["buy"],
    description: "Buy credits / check balance",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "credits",
      });
    },
  },

  {
    name: "create-skill",
    description: "Create a new operator skill",
    category: "Skills",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "create-skill",
      });
    },
  },

  // Add more commands here...
  // Example:
  // {
  //   name: "clear",
  //   aliases: ["cls"],
  //   description: "Clear the screen",
  //   category: "General",
  //   handler: async (args, ctx) => {
  //     ctx.clearScreen?.();
  //   },
  // },
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

import type { CommandDefinition } from "./command-router";

/**
 * Define your application's CommandContext type with specific methods
 */
export interface AppCommandContext {
  openHelp: () => void;
  openConfig: () => void;
  openPentest: () => void;
  openThoroughPentest: () => void;
  openSessions: () => void;
  openModels: () => void;
  // Add more context methods here as needed
  // clearScreen?: () => void;
  // showMessage?: (msg: string) => void;
}

/**
 * Command configuration object - easy to map over and export
 */
export interface CommandConfig {
  name: string;
  aliases?: string[];
  description?: string;
  category?: string;
  handler: (args: string[], ctx: AppCommandContext) => void | Promise<void>;
}

/**
 * All available commands in a simple, mappable array
 */
export const commands: CommandConfig[] = [
  {
    name: "help",
    description: "Show help dialog",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openHelp();
    },
  },
  {
    name: "config",
    description: "Show config dialog",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openConfig();
    },
  },
  {
    name: "pentest",
    description: "Show pentest agent",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openPentest();
    },
  },
  {
    name: "thorough",
    aliases: ["thorough-pentest", "comprehensive"],
    description: "Show thorough pentest agent (orchestrator)",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openThoroughPentest();
    },
  },
  {
    name: "sessions",
    description: "Show available sessions",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openSessions();
    },
  },
  {
    name: "models",
    description: "Show available AI models",
    category: "General",
    handler: async (args, ctx) => {
      ctx.openModels();
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

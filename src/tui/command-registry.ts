import type { CommandDefinition } from "./command-router";
import type { Route } from "./context/route";

/**
 * Define your application's CommandContext type with specific methods
 */
export interface AppCommandContext {
  route: Route;
  navigate: (route: Route) => void;
};

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
      ctx.navigate({
        type: "base",
        path: "help"
      });
    },
  },
  // {
  //   name: "config",
  //   description: "Show config dialog",
  //   category: "General",
  //   handler: async (args, ctx) => {
  //     ctx.navigate({
  //       type: "base",
  //       path: "config"
  //     });
  //   },
  // },
  // {
  //   name: "quicktest",
  //   description: "Show quick pentest agent",
  //   category: "General",
  //   handler: async (args, ctx) => {
  //     ctx.navigate({
  //       type: "base",
  //       path: "pentest"
  //     });
  //   },
  // },
  // {
  //   name: "pentest",
  //   description: "Show pentest agent",
  //   category: "General",
  //   handler: async (args, ctx) => {
  //     ctx.navigate({
  //       type: "base",
  //       path: "thorough"
  //     });
  //   },
  // },
  {
    name: "web",
    aliases: ["w"],
    description: "Start a web app pentest session",
    category: "Pentesting",
    options: [
      { name: "--target", description: "Target URL to test", valueHint: "<url>" },
      { name: "--auto", description: "Enable auto swarm mode" },
    ],
    handler: async (args, ctx) => {
      const hasAuto = args.includes('--auto');
      const targetIdx = args.indexOf('--target');
      const target = targetIdx !== -1 ? args[targetIdx + 1] : undefined;
      ctx.navigate({
        type: "base",
        path: "web",
        options: { auto: hasAuto, target }
      });
    },
  },
  {
    name: "operator",
    aliases: ["h"],
    description: "Start interactive pentesting session (Human-in-the-Loop)",
    category: "Pentesting",
    options: [
      { name: "--target", description: "Target URL to test", valueHint: "<url>" },
      { name: "--mode", description: "Approval mode: plan, manual, or auto", valueHint: "<mode>" },
    ],
    handler: async (args, ctx) => {
      const targetIdx = args.indexOf('--target');
      const target = targetIdx !== -1 ? args[targetIdx + 1] : undefined;
      const modeIdx = args.indexOf('--mode');
      const mode = modeIdx !== -1 ? args[modeIdx + 1] : undefined;
      ctx.navigate({
        type: "base",
        path: "operator",
        options: { target, mode } as any
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
        path: "models"
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
        path: "providers"
      });
    },
  },
  {
    name: "resume",
    aliases: ["r"],
    description: "Resume a previous pentest session",
    category: "Pentesting",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "resume"
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

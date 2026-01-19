import type { CommandDefinition } from "./command-router";
import type { Route } from "./context/route";
import {
  parseWebFlags,
  hasEnoughFlagsToSkipWizard,
  createOperatorSessionFromFlags,
  createSwarmSessionFromFlags,
} from "./utils/command-flags";

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
    description: "Start web pentest (use /help for flags)",
    category: "Pentesting",
    handler: async (args, ctx) => {
      const flags = parseWebFlags(args);

      if (flags.swarm) {
        // Swarm mode path
        if (flags.target && hasEnoughFlagsToSkipWizard(flags)) {
          try {
            const session = await createSwarmSessionFromFlags(flags);
            ctx.navigate({ type: "session", sessionId: session.id });
            return;
          } catch (e) {
            // Fall through to wizard on error
            console.error("Failed to create session:", e);
          }
        }
        // Navigate to WebWizard (swarm wizard)
        ctx.navigate({
          type: "base",
          path: "web",
          options: { auto: true, ...flags }
        });
        return;
      }

      // Operator mode path (default)
      if (flags.target && hasEnoughFlagsToSkipWizard(flags)) {
        try {
          const session = await createOperatorSessionFromFlags(flags);
          ctx.navigate({ type: "session", sessionId: session.id });
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
        options: flags as any
      });
    },
  },
  {
    name: "operator",
    aliases: ["h"],
    description: "Start HITL pentest session",
    category: "Pentesting",
    handler: async (args, ctx) => {
      const flags = parseWebFlags(args);

      // Operator mode - skip wizard if enough flags provided
      if (flags.target && hasEnoughFlagsToSkipWizard(flags)) {
        try {
          const session = await createOperatorSessionFromFlags(flags);
          ctx.navigate({ type: "session", sessionId: session.id });
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
        options: flags as any
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
  {
    name: "chat",
    aliases: ["c"],
    description: "Open the Chat TUI interface",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "chat"
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

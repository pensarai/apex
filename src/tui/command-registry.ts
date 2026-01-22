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
  {
    name: "config",
    description: "Show config dialog",
    category: "General",
    handler: async (args, ctx) => {
      ctx.navigate({
        type: "base",
        path: "config"
      });
    },
  },
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
    description: "Start web pentest session",
    category: "Pentesting",
    options: [
      { name: "--target", valueHint: "<url>", description: "Target URL to test" },
      { name: "--name", valueHint: "<name>", description: "Session name" },
      { name: "--swarm", description: "Use autonomous swarm mode" },
      { name: "--mode", valueHint: "<plan|manual|auto>", description: "Operator mode" },
      { name: "--tier", valueHint: "<1-5>", description: "Auto-approve permission tier" },
      { name: "--auth-url", valueHint: "<url>", description: "Login page URL" },
      { name: "--auth-user", valueHint: "<user>", description: "Auth username" },
      { name: "--auth-pass", valueHint: "<pass>", description: "Auth password" },
      { name: "--auth-instructions", valueHint: "<text>", description: "Auth instructions" },
      { name: "--hosts", valueHint: "<h1,h2,...>", description: "Allowed hosts" },
      { name: "--ports", valueHint: "<p1,p2,...>", description: "Allowed ports" },
      { name: "--strict", description: "Enable strict scope mode" },
      { name: "--headers", valueHint: "<none|default|custom>", description: "Headers mode" },
      { name: "--header", valueHint: "<Name:Value>", description: "Custom header (repeatable)" },
      { name: "--model", valueHint: "<model>", description: "AI model to use" },
    ],
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
  {
    name: "tools",
    aliases: ["t"],
    description: "View and manage active tools (session only)",
    category: "Session",
    handler: async (args, ctx) => {
      // This command is handled by the session view when in a session
      // From home, it does nothing - tools panel only works in session context
      if (ctx.route.type !== "session") {
        // Not in a session - command is a no-op
        return;
      }
      // The session view will detect this command via route options
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

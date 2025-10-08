import type { CommandDefinition } from "./command-router";

/**
 * Define your application's CommandContext type with specific methods
 */
export interface CommandContext {
  openHelp: () => void;
  // Add more context methods here as needed
  // clearScreen?: () => void;
  // showMessage?: (msg: string) => void;
}

/**
 * Registry of all available commands.
 * Each command definition receives the context and returns a command configuration.
 */
export const commandRegistry: CommandDefinition<CommandContext>[] = [
  // Help command
  (ctx) => ({
    name: "help",
    aliases: ["?"],
    description: "Show help dialog",
    handler: async () => {
      console.log("[help command] handler called, calling ctx.openHelp()");
      ctx.openHelp();
      console.log("[help command] ctx.openHelp() called");
    },
  }),

  // Add more commands here...
  // Example:
  // (ctx) => ({
  //   name: "clear",
  //   aliases: ["cls"],
  //   description: "Clear the screen",
  //   handler: async () => {
  //     ctx.clearScreen();
  //   },
  // }),
];

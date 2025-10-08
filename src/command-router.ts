import type { AppCommandContext } from "./command-registry";

export type CommandHandler<TContext = AppCommandContext> = (
  args: string[],
  ctx: TContext
) => void | Promise<void>;

export interface Command<TContext = AppCommandContext> {
  name: string;
  aliases?: string[];
  description?: string;
  handler: CommandHandler<TContext>;
}

// Command definition that accepts context
export type CommandDefinition<TContext = AppCommandContext> = (
  ctx: TContext
) => Omit<Command<TContext>, "handler"> & {
  handler: (args: string[]) => void | Promise<void>;
};

export class CommandRouter<TContext = AppCommandContext> {
  private nameToCommand: Map<string, Command<TContext>> = new Map();
  private commands: Command<TContext>[] = [];

  register(command: Command<TContext>) {
    this.commands.push(command);
    const names = [command.name, ...(command.aliases ?? [])].map((n) =>
      n.toLowerCase()
    );
    for (const n of names) this.nameToCommand.set(n, command);
  }

  /**
   * Register a command definition that will be bound to a context
   */
  registerWithContext(definition: CommandDefinition<TContext>, ctx: TContext) {
    const { handler, ...metadata } = definition(ctx);
    this.register({
      ...metadata,
      handler: (args) => handler(args),
    });
  }

  getAllCommands(): Command<TContext>[] {
    return this.commands;
  }

  parse(input: string): { name: string | null; args: string[] } {
    if (!input) return { name: null, args: [] };
    let text = input.trim();
    // Collapse multiple leading slashes ("//help") and spaces
    text = text.replace(/^\/+/, "/");
    // Allow both "/help" and "/ help"
    if (text.startsWith("/")) text = text.slice(1).trimStart();
    if (text.length === 0) return { name: null, args: [] };
    const [rawName, ...args] = text.split(/\s+/);
    const name = (rawName ?? "").toLowerCase();
    if (!name) return { name: null, args };
    return { name, args };
  }

  async execute(input: string, ctx: TContext): Promise<boolean> {
    const { name, args } = this.parse(input);
    if (!name) return false;
    const cmd = this.nameToCommand.get(name);
    if (!cmd) return false;
    await cmd.handler(args, ctx);
    return true;
  }
}

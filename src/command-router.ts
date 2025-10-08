import type { CommandContext } from "./command-registry";

export type CommandHandler<TContext = CommandContext> = (
  args: string[],
  ctx: TContext
) => void | Promise<void>;

export interface Command<TContext = CommandContext> {
  name: string;
  aliases?: string[];
  description?: string;
  handler: CommandHandler<TContext>;
}

// Command definition that accepts context
export type CommandDefinition<TContext = CommandContext> = (
  ctx: TContext
) => Omit<Command<TContext>, "handler"> & {
  handler: (args: string[]) => void | Promise<void>;
};

export class CommandRouter<TContext = CommandContext> {
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
    console.log("[CommandRouter] execute called with input:", input);
    const { name, args } = this.parse(input);
    console.log("[CommandRouter] parsed - name:", name, "args:", args);
    if (!name) {
      console.log("[CommandRouter] no name, returning false");
      return false;
    }
    const cmd = this.nameToCommand.get(name);
    console.log("[CommandRouter] found command:", cmd ? cmd.name : "NOT FOUND");
    if (!cmd) {
      console.log(
        "[CommandRouter] command not found, available:",
        Array.from(this.nameToCommand.keys())
      );
      return false;
    }
    console.log("[CommandRouter] executing handler for:", cmd.name);
    await cmd.handler(args, ctx);
    console.log("[CommandRouter] handler executed successfully");
    return true;
  }
}

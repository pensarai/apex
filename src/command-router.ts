export type CommandHandler = (
  args: string[],
  ctx: CommandContext
) => void | Promise<void>;

export interface Command {
  name: string;
  aliases?: string[];
  description?: string;
  handler: CommandHandler;
}

export interface CommandContext {
  openHelp: () => void;
}

export class CommandRouter {
  private nameToCommand: Map<string, Command> = new Map();
  private commands: Command[] = [];

  register(command: Command) {
    this.commands.push(command);
    const names = [command.name, ...(command.aliases ?? [])].map((n) =>
      n.toLowerCase()
    );
    for (const n of names) this.nameToCommand.set(n, command);
  }

  getAllCommands(): Command[] {
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

  async execute(input: string, ctx: CommandContext): Promise<boolean> {
    const { name, args } = this.parse(input);
    if (!name) return false;
    const cmd = this.nameToCommand.get(name);
    if (!cmd) return false;
    await cmd.handler(args, ctx);
    return true;
  }
}

export function createDefaultRouter(ctx: CommandContext) {
  const router = new CommandRouter();

  router.register({
    name: "help",
    aliases: ["?"],
    description: "Show help dialog",
    handler: async () => {
      ctx.openHelp();
    },
  });

  return router;
}

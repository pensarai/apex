import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
} from "react";
import type { ReactNode } from "react";
import { CommandRouter } from "./command-router";
import { commandRegistry, type CommandContext } from "./command-registry";
import type { AutocompleteOption } from "./components /autocomplete";

interface CommandContextValue {
  router: CommandRouter<CommandContext>;
  autocompleteOptions: AutocompleteOption[];
  executeCommand: (input: string) => Promise<boolean>;
  helpOpen: boolean;
  openHelp: () => void;
  closeHelp: () => void;
}

const CommandContext = createContext<CommandContextValue | null>(null);

export function useCommand(): CommandContextValue {
  const context = useContext(CommandContext);
  if (!context) {
    throw new Error("useCommand must be used within CommandProvider");
  }
  return context;
}

interface CommandProviderProps {
  children: ReactNode;
}

export function CommandProvider({ children }: CommandProviderProps) {
  const [helpOpen, setHelpOpen] = useState(false);

  // Create router with context - initialized once
  const router = useMemo(() => {
    const router = new CommandRouter<CommandContext>();

    // Create context with stable references to state setters
    const ctx: CommandContext = {
      openHelp: () => {
        console.log("openHelp called from registered command context");
        setHelpOpen(true);
      },
    };

    console.log("[CommandProvider] Registering commands...");
    // Register all commands from the registry
    for (const commandDef of commandRegistry) {
      const command = commandDef(ctx);
      console.log("[CommandProvider] Registering command:", command.name);
      router.registerWithContext(commandDef, ctx);
    }
    console.log("[CommandProvider] All commands registered");

    return router;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Generate autocomplete options from router commands
  const autocompleteOptions = useMemo((): AutocompleteOption[] => {
    const commands = router.getAllCommands();
    const options: AutocompleteOption[] = [];

    for (const cmd of commands) {
      // Add main command
      options.push({
        value: `/${cmd.name}`,
        label: `/${cmd.name}`,
        description: cmd.description,
      });

      // Add aliases
      if (cmd.aliases) {
        for (const alias of cmd.aliases) {
          options.push({
            value: `/${alias}`,
            label: `/${alias}`,
            description: `Alias for /${cmd.name}`,
          });
        }
      }
    }

    return options;
  }, [router]);

  const executeCommand = useCallback(
    async (input: string): Promise<boolean> => {
      console.log("executeCommand called with input:", input);
      const ctx: CommandContext = {
        openHelp: () => {
          console.log("openHelp called from executeCommand ctx");
          setHelpOpen(true);
        },
      };

      const result = await router.execute(input, ctx);
      console.log("execute result:", result);
      return result;
    },
    [router]
  );

  const value: CommandContextValue = useMemo(
    () => ({
      router,
      autocompleteOptions,
      executeCommand,
      helpOpen,
      openHelp: () => {
        console.log("openHelp called from context value");
        setHelpOpen(true);
      },
      closeHelp: () => setHelpOpen(false),
    }),
    [router, autocompleteOptions, executeCommand, helpOpen]
  );

  return (
    <CommandContext.Provider value={value}>{children}</CommandContext.Provider>
  );
}

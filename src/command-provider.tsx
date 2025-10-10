import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
  useEffect,
} from "react";
import type { ReactNode } from "react";
import { CommandRouter } from "./command-router";
import {
  commandRegistry,
  commands,
  type AppCommandContext,
} from "./command-registry";
import type { AutocompleteOption } from "./components/autocomplete";

interface CommandContextValue {
  router: CommandRouter<AppCommandContext>;
  autocompleteOptions: AutocompleteOption[];
  executeCommand: (input: string) => Promise<boolean>;
  helpOpen: boolean;
  openHelp: () => void;
  closeHelp: () => void;
  configOpen: boolean;
  openConfig: () => void;
  closeConfig: () => void;
  pentestOpen: boolean;
  openPentest: () => void;
  closePentest: () => void;
  sessionsOpen: boolean;
  openSessions: () => void;
  closeSessions: () => void;
  commands: typeof commands;
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
  const [configOpen, setConfigOpen] = useState(false);
  const [pentestOpen, setPentestOpen] = useState(false);
  const [sessionsOpen, setSessionsOpen] = useState(false);

  // Create router with context - initialized once
  const router = useMemo(() => {
    const router = new CommandRouter<AppCommandContext>();

    // Create context with stable references to state setters
    const ctx: AppCommandContext = {
      openHelp: () => setHelpOpen(true),
      openConfig: () => setConfigOpen(true),
      openPentest: () => setPentestOpen(true),
      openSessions: () => setSessionsOpen(true),
    };

    // Register all commands from the registry
    for (const commandDef of commandRegistry) {
      router.registerWithContext(commandDef, ctx);
    }

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
      const ctx: AppCommandContext = {
        openHelp: () => setHelpOpen(true),
        openConfig: () => setConfigOpen(true),
        openPentest: () => setPentestOpen(true),
        openSessions: () => setSessionsOpen(true),
      };

      return await router.execute(input, ctx);
    },
    [router]
  );

  const value: CommandContextValue = useMemo(
    () => ({
      router,
      autocompleteOptions,
      executeCommand,
      helpOpen,
      openHelp: () => setHelpOpen(true),
      closeHelp: () => setHelpOpen(false),
      configOpen,
      openConfig: () => setConfigOpen(true),
      closeConfig: () => setConfigOpen(false),
      pentestOpen,
      openPentest: () => setPentestOpen(true),
      closePentest: () => setPentestOpen(false),
      sessionsOpen,
      openSessions: () => setSessionsOpen(true),
      closeSessions: () => setSessionsOpen(false),
      commands,
    }),
    [
      router,
      autocompleteOptions,
      executeCommand,
      helpOpen,
      configOpen,
      pentestOpen,
      sessionsOpen,
    ]
  );

  return (
    <CommandContext.Provider value={value}>{children}</CommandContext.Provider>
  );
}

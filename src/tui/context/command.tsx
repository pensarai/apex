import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
  useEffect,
} from "react";
import type { ReactNode } from "react";
import { CommandRouter } from "../command-router";
import {
  commandRegistry,
  commands,
  type AppCommandContext,
} from "../command-registry";
import type { AutocompleteOption } from "../components/autocomplete";
import { useRoute } from "./route";

interface CommandContextValue {
  router: CommandRouter<AppCommandContext>;
  autocompleteOptions: AutocompleteOption[];
  executeCommand: (input: string) => Promise<boolean>;
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
  const route = useRoute();

  const ctx = useMemo(() => {
    const ctx: AppCommandContext = {
      route: route.data,
      navigate: route.navigate
    }
    return ctx
  }, [route]);

  // Create router with context - initialized once
  const router = useMemo(() => {
    const router = new CommandRouter<AppCommandContext>();

    // Register all commands from the registry
    for (const commandDef of commandRegistry) {
      router.registerWithContext(commandDef, ctx);
    }

    return router;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Generate autocomplete options from router commands
  const autocompleteOptions = useMemo((): AutocompleteOption[] => {
    const routerCommands = router.getAllCommands();
    const options: AutocompleteOption[] = [];

    for (const cmd of routerCommands) {
      // Find the original command config to get options
      const cmdConfig = commands.find((c) => c.name === cmd.name);

      // Build description with options hint
      let description = cmd.description || "";

      // Add main command (aliases hidden but still work via router)
      options.push({
        value: `/${cmd.name}`,
        label: `/${cmd.name}`,
        description,
      });
    }

    return options;
  }, [router]);

  const executeCommand = useCallback(
    async (input: string): Promise<boolean> => {
      return await router.execute(input, ctx);
    },
    [router, ctx]
  );

  const value: CommandContextValue = useMemo(
    () => ({
      router,
      autocompleteOptions,
      executeCommand,
      commands,
    }),
    [
      router,
      autocompleteOptions,
      executeCommand,
    ]
  );

  return (
    <CommandContext.Provider value={value}>{children}</CommandContext.Provider>
  );
}

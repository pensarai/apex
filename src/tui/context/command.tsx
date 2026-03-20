import {
  createContext,
  useContext,
  useMemo,
  useCallback,
  useState,
  useEffect,
} from "react";
import type { ReactNode } from "react";
import { CommandRouter } from "../command-router";
import {
  commandRegistry,
  commands,
  type AppCommandContext,
} from "../command-registry";
import type { AutocompleteOption } from "../components/shared/prompt-input";
import { useRoute, type WebCommandOptions } from "./route";
import { createSkillsRegistry, type SkillsRegistry } from "../../core/skills";

interface CommandContextValue {
  router: CommandRouter<AppCommandContext>;
  autocompleteOptions: AutocompleteOption[];
  executeCommand: (input: string) => Promise<boolean>;
  commands: typeof commands;
  /** Reload skills from disk (e.g. after creating a new one) */
  refreshSkills: () => Promise<void>;
  /**
   * Resolve a slash-command input to skill content.
   * Returns the skill's description if the input matches a skill, else null.
   */
  resolveSkillContent: (input: string) => string | null;
  /** Skills registry */
  skillsRegistry: SkillsRegistry;
  /** Incremented on each registry refresh — use as a memo dependency to react to skill changes */
  skillsVersion: number;
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
  onOpenSessionsDialog?: () => void;
  onOpenThemeDialog?: () => void;
  onOpenModelDialog?: () => void;
  onOpenProvidersDialog?: () => void;
  onOpenCreditsDialog?: () => void;
  onOpenHelpDialog?: () => void;
  onOpenAuthDialog?: () => void;
  onOpenPentestDialog?: (flags?: WebCommandOptions) => void;
}

export function CommandProvider({
  children,
  onOpenSessionsDialog,
  onOpenThemeDialog,
  onOpenModelDialog,
  onOpenProvidersDialog,
  onOpenCreditsDialog,
  onOpenHelpDialog,
  onOpenAuthDialog,
  onOpenPentestDialog,
}: CommandProviderProps) {
  const route = useRoute();
  const [registry] = useState(() => createSkillsRegistry());
  const [registryVersion, setRegistryVersion] = useState(0);

  const ctx = useMemo(() => {
    const ctx: AppCommandContext = {
      route: route.data,
      navigate: route.navigate,
      openSessionsDialog: onOpenSessionsDialog,
      openThemeDialog: onOpenThemeDialog,
      openModelDialog: onOpenModelDialog,
      openProvidersDialog: onOpenProvidersDialog,
      openCreditsDialog: onOpenCreditsDialog,
      openHelpDialog: onOpenHelpDialog,
      openAuthDialog: onOpenAuthDialog,
      openPentestDialog: onOpenPentestDialog,
    };
    return ctx;
  }, [
    route,
    onOpenSessionsDialog,
    onOpenThemeDialog,
    onOpenModelDialog,
    onOpenProvidersDialog,
    onOpenCreditsDialog,
    onOpenHelpDialog,
    onOpenAuthDialog,
    onOpenPentestDialog,
  ]);

  const refreshSkills = useCallback(async () => {
    await registry.refresh();
    setRegistryVersion((v) => v + 1);
  }, [registry]);

  // Load skills + registry on mount and whenever we return to home
  useEffect(() => {
    registry.load({ projectRoot: process.cwd() }).then(() => {
      setRegistryVersion((v) => v + 1);
    });
  }, [route.data]);

  // Create router with context - initialized once
  const router = useMemo(() => {
    const router = new CommandRouter<AppCommandContext>();

    // Register all commands from the registry
    for (const commandDef of commandRegistry) {
      router.registerWithContext(commandDef, ctx);
    }

    return router;
  }, []);

  const resolveSkillContent = useCallback(
    (input: string): string | null => {
      const trimmed = input.trim().replace(/^\/+/, "").toLowerCase();
      const entry = registry.get(trimmed);
      if (entry) {
        return entry.manifest.description;
      }
      return null;
    },
    [registry, registryVersion],
  );

  // Generate autocomplete options from router commands + skills.
  // Order is determined by the commands array in command-registry.ts.
  const autocompleteOptions = useMemo((): AutocompleteOption[] => {
    const routerCommands = router.getAllCommands();
    const options: AutocompleteOption[] = [];

    for (const cmd of routerCommands) {
      const cmdConfig = commands.find((c) => c.name === cmd.name);
      if (cmdConfig?.hidden) continue;

      const description = cmd.description || "";
      options.push({
        value: `/${cmd.name}`,
        label: `/${cmd.name}`,
        description,
      });
    }

    // Append skills from registry (already deduplicated by slug)
    for (const entry of registry.list()) {
      options.push({
        value: `/${entry.slug}`,
        label: `/${entry.slug}`,
        description: entry.manifest.description || "Skill",
      });
    }

    return options;
  }, [router, registry, registryVersion]);

  const executeCommand = useCallback(
    async (input: string): Promise<boolean> => {
      return await router.execute(input, ctx);
    },
    [router, ctx],
  );

  const value: CommandContextValue = useMemo(
    () => ({
      router,
      autocompleteOptions,
      executeCommand,
      commands,
      refreshSkills,
      resolveSkillContent,
      skillsRegistry: registry,
      skillsVersion: registryVersion,
    }),
    [
      router,
      autocompleteOptions,
      executeCommand,
      refreshSkills,
      resolveSkillContent,
      registry,
      registryVersion,
    ],
  );

  return (
    <CommandContext.Provider value={value}>{children}</CommandContext.Provider>
  );
}

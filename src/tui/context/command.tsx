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
import {
  slugify,
  createSkillsRegistry,
  type Skill,
  type SkillsRegistry,
} from "../../core/skills";

interface CommandContextValue {
  router: CommandRouter<AppCommandContext>;
  autocompleteOptions: AutocompleteOption[];
  executeCommand: (input: string) => Promise<boolean>;
  commands: typeof commands;
  /** Available operator skills loaded from ~/.pensar/skills/ */
  skills: Skill[];
  /** Reload skills from disk (e.g. after creating a new one) */
  refreshSkills: () => Promise<void>;
  /**
   * Resolve a slash-command input to skill content.
   * Returns the skill's prompt content if the input matches a skill, else null.
   */
  resolveSkillContent: (input: string) => string | null;
  /** skills.sh-compatible registry (includes both legacy and directory-based skills) */
  skillsRegistry: SkillsRegistry;
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
  onOpenAuthDialog?: () => void;
  onOpenPentestDialog?: (flags?: WebCommandOptions) => void;
}

export function CommandProvider({
  children,
  onOpenSessionsDialog,
  onOpenThemeDialog,
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
      openAuthDialog: onOpenAuthDialog,
      openPentestDialog: onOpenPentestDialog,
    };
    return ctx;
  }, [
    route,
    onOpenSessionsDialog,
    onOpenThemeDialog,
    onOpenAuthDialog,
    onOpenPentestDialog,
  ]);

  const refreshSkills = useCallback(async () => {
    await registry.refresh();
    setRegistryVersion((v) => v + 1);
  }, [registry]);

  // Load skills + registry on mount and whenever we return to home
  useEffect(() => {
    refreshSkills();
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

  // Derive legacy Skill[] from the registry (single source of truth)
  const skills = useMemo(
    () => registry.toLegacySkills(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [registry, registryVersion],
  );

  const resolveSkillContent = useCallback(
    (input: string): string | null => {
      const trimmed = input.trim().replace(/^\/+/, "").toLowerCase();
      // Activation is intentional here: slash-command invocation implies the
      // operator wants the skill active so its instructions enter the system prompt.
      const entry = registry.get(trimmed);
      if (entry?.enabled) {
        registry.activate(trimmed);
        return entry.instructions;
      }
      return null;
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [registry, registryVersion],
  );

  // Generate autocomplete options from router commands + skills
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
    for (const entry of registry.listEnabled()) {
      options.push({
        value: `/${entry.slug}`,
        label: `/${entry.slug}`,
        description: entry.manifest.description || "Skill",
      });
    }

    // Sort commands with priority order first, then others alphabetically
    const priorityOrder = [
      "/pentest",
      "/operator",
      "/auth",
      "/models",
      "/sessions",
      "/themes",
      "/help",
    ];

    return options.sort((a, b) => {
      const aIndex = priorityOrder.indexOf(a.value);
      const bIndex = priorityOrder.indexOf(b.value);

      // Both in priority list - sort by priority order
      if (aIndex !== -1 && bIndex !== -1) {
        return aIndex - bIndex;
      }

      // Only a is in priority list - a comes first
      if (aIndex !== -1) return -1;

      // Only b is in priority list - b comes first
      if (bIndex !== -1) return 1;

      // Neither in priority list - sort alphabetically
      return a.value.localeCompare(b.value);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router]);

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
      skills,
      refreshSkills,
      resolveSkillContent,
      skillsRegistry: registry,
    }),
    [
      router,
      autocompleteOptions,
      executeCommand,
      skills,
      refreshSkills,
      resolveSkillContent,
      registry,
    ],
  );
  // Note: `skills` is derived from `registry` via `registryVersion`, so it
  // naturally updates when the registry refreshes. No duplicate disk scans.

  return (
    <CommandContext.Provider value={value}>{children}</CommandContext.Provider>
  );
}

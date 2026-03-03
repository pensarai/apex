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
import { useRoute } from "./route";
import { loadSkills, slugify, type Skill } from "../../core/skills";

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
  const [skills, setSkills] = useState<Skill[]>([]);

  const ctx = useMemo(() => {
    const ctx: AppCommandContext = {
      route: route.data,
      navigate: route.navigate,
    };
    return ctx;
  }, [route]);

  const refreshSkills = useCallback(async () => {
    const loaded = await loadSkills();
    setSkills(loaded);
  }, []);

  // Load skills on mount and whenever we return to home
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

  // Build a slug-to-content map for fast skill resolution
  const skillSlugMap = useMemo(() => {
    const map = new Map<string, Skill>();
    for (const skill of skills) {
      map.set(slugify(skill.name), skill);
    }
    return map;
  }, [skills]);

  const resolveSkillContent = useCallback(
    (input: string): string | null => {
      const trimmed = input.trim().replace(/^\/+/, "").toLowerCase();
      const skill = skillSlugMap.get(trimmed);
      return skill?.content ?? null;
    },
    [skillSlugMap],
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

    // Append skill-based slash commands
    for (const skill of skills) {
      const slug = slugify(skill.name);
      options.push({
        value: `/${slug}`,
        label: `/${slug}`,
        description: skill.description || "Skill",
      });
    }

    return options;
  }, [router, skills]);

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
    }),
    [
      router,
      autocompleteOptions,
      executeCommand,
      skills,
      refreshSkills,
      resolveSkillContent,
    ],
  );

  return (
    <CommandContext.Provider value={value}>{children}</CommandContext.Provider>
  );
}

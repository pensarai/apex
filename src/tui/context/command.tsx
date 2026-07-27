import type { ReactNode } from "react";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { isObfuscationEnabled } from "../../core/obfuscation";
import { createSkillsRegistry, type SkillsRegistry } from "../../core/skills";
import {
  type AppCommandContext,
  commandRegistry,
  commands,
} from "../command-registry";
import { CommandRouter } from "../command-router";
import type { AutocompleteOption } from "../components/shared";
import { useObfuscation } from "./obfuscation";
import { useRoute, type WebCommandOptions } from "./route";
import { useToast } from "./toast";

interface CommandContextValue {
  router: CommandRouter<AppCommandContext>;
  autocompleteOptions: AutocompleteOption[];
  /** Map from command name/alias → AutocompleteOption[] for that command's --options */
  commandOptionMap: Map<string, AutocompleteOption[]>;
  /** Set of all command names + aliases (for option detection) */
  commandNames: Set<string>;
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
  onOpenAdvancedDialog?: () => void;
  onOpenModelDialog?: () => void;
  onOpenProvidersDialog?: () => void;
  onOpenCreditsDialog?: () => void;
  onOpenHelpDialog?: () => void;
  onOpenAuthDialog?: () => void;
  onOpenPentestDialog?: (flags?: WebCommandOptions) => void;
  onOpenSkillsDialog?: (slug?: string) => void;
}

export function CommandProvider({
  children,
  onOpenSessionsDialog,
  onOpenThemeDialog,
  onOpenAdvancedDialog,
  onOpenModelDialog,
  onOpenProvidersDialog,
  onOpenCreditsDialog,
  onOpenHelpDialog,
  onOpenAuthDialog,
  onOpenPentestDialog,
  onOpenSkillsDialog,
}: CommandProviderProps) {
  const route = useRoute();
  const obfuscation = useObfuscation();
  const { toast } = useToast();
  const [registry] = useState(() => createSkillsRegistry());
  const [registryVersion, setRegistryVersion] = useState(0);

  const ctx = useMemo(() => {
    const ctx: AppCommandContext = {
      route: route.data,
      navigate: route.navigate,
      openSessionsDialog: onOpenSessionsDialog,
      openThemeDialog: onOpenThemeDialog,
      openAdvancedDialog: onOpenAdvancedDialog,
      openModelDialog: onOpenModelDialog,
      openProvidersDialog: onOpenProvidersDialog,
      openCreditsDialog: onOpenCreditsDialog,
      openHelpDialog: onOpenHelpDialog,
      openAuthDialog: onOpenAuthDialog,
      openPentestDialog: onOpenPentestDialog,
      openSkillsDialog: onOpenSkillsDialog,
      setObfuscation: (enabled) => {
        // Read live engine state so toast feedback is accurate even if
        // this closure was captured on an earlier render. The provider's
        // `setEnabled` is itself idempotent against stale closures.
        const current = isObfuscationEnabled();
        const next = typeof enabled === "boolean" ? enabled : !current;
        obfuscation.setEnabled(next);
        return next;
      },
      getObfuscation: () => isObfuscationEnabled(),
      toast,
    };
    return ctx;
  }, [
    route,
    onOpenSessionsDialog,
    onOpenThemeDialog,
    onOpenAdvancedDialog,
    onOpenModelDialog,
    onOpenProvidersDialog,
    onOpenCreditsDialog,
    onOpenHelpDialog,
    onOpenAuthDialog,
    onOpenPentestDialog,
    onOpenSkillsDialog,
    obfuscation,
    toast,
  ]);

  const refreshSkills = useCallback(async () => {
    await registry.refresh();
    setRegistryVersion((v) => v + 1);
  }, [registry]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `route.data` is an intentional trigger — reloads skills whenever the user navigates back to home.
  useEffect(() => {
    registry.load({ projectRoot: process.cwd() }).then(() => {
      setRegistryVersion((v) => v + 1);
    });
  }, [registry.load, route.data]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `ctx` is intentionally omitted — registerWithContext only extracts static metadata (name, aliases, description) at registration time; handlers are re-bound with live ctx on every execute() call (see command-router.ts).
  const router = useMemo(() => {
    const router = new CommandRouter<AppCommandContext>();

    for (const commandDef of commandRegistry) {
      router.registerWithContext(commandDef, ctx);
    }

    return router;
  }, []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `registryVersion` is an intentional cache-buster — forces recomputation when skills are refreshed even though `registry` (stable ref) hasn't changed.
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

  // biome-ignore lint/correctness/useExhaustiveDependencies: `registryVersion` is an intentional cache-buster — forces recomputation when skills are refreshed even though `registry` (stable ref) hasn't changed.
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

    // Append skills from registry, skipping any that already have a command entry
    const commandNames = new Set<string>();
    for (const cmd of routerCommands) {
      commandNames.add(cmd.name);
      for (const alias of cmd.aliases ?? []) {
        commandNames.add(alias);
      }
    }
    for (const entry of registry.list()) {
      if (commandNames.has(entry.slug)) continue;
      options.push({
        value: `/${entry.slug}`,
        label: `/${entry.slug}`,
        description: entry.manifest.description || "Skill",
      });
    }

    return options;
  }, [router, registry, registryVersion]);

  // Build option map: command name/alias → AutocompleteOption[] for --flags
  const commandOptionMap = useMemo(() => {
    const map = new Map<string, AutocompleteOption[]>();
    for (const cmd of commands) {
      if (!cmd.options?.length) continue;
      const opts: AutocompleteOption[] = cmd.options
        .filter((o) => o.name.startsWith("--"))
        .map((o) => ({
          value: o.name,
          label: o.name + (o.valueHint ? ` ${o.valueHint}` : ""),
          description: o.description,
        }));
      if (opts.length === 0) continue;
      map.set(cmd.name, opts);
      for (const alias of cmd.aliases ?? []) {
        map.set(alias, opts);
      }
    }
    return map;
  }, []);

  // Set of all command names + aliases for option detection
  const commandNames = useMemo(() => {
    const names = new Set<string>();
    for (const cmd of commands) {
      if (cmd.hidden) continue;
      names.add(cmd.name);
      for (const alias of cmd.aliases ?? []) names.add(alias);
    }
    return names;
  }, []);

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
      commandOptionMap,
      commandNames,
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
      commandOptionMap,
      commandNames,
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

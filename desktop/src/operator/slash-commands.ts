import type { OperatorSnapshot } from "./contract";

export type SlashEntry = {
  slug: string;
  description: string;
  kind: "command" | "skill";
};
export const COMMAND_ALIASES: Record<string, string> = {
  o: "operator",
  w: "pentest",
  p: "pentest",
  web: "pentest",
  s: "resume",
  sessions: "resume",
  tm: "threat-model",
  pi: "prompt-injection",
  t: "tools",
  auth: "login",
  buy: "credits",
  redact: "obfuscate",
  "advanced-settings": "advanced",
  theme: "themes",
  model: "models",
  q: "exit",
  quit: "exit",
};

const commands = {
  goal: "Work toward an objective · /goal <objective> [--rounds N]",
  new: "Start a new session",
  operator: "Configure an operator session",
  pentest: "Start a penetration test",
  resume: "Browse or resume saved sessions",
  runs: "Browse recorded runs",
  "threat-model": "Build a threat model",
  "prompt-injection": "Test prompt injection",
  tools: "Choose available tools",
  models: "Choose a model",
  effort: "Configure reasoning effort",
  providers: "Configure AI providers",
  login: "Manage your account",
  credits: "View credits",
  themes: "Change appearance",
  obfuscate: "Toggle sensitive value masking",
  advanced: "Configure execution settings",
  headers: "Configure session HTTP headers",
  plan: "View the session plan",
  skills: "Browse available skills",
  "open-session": "Open the session folder",
  help: "Show command help",
  exit: "Quit Apex",
} satisfies Record<string, string>;

export function slashEntries(
  text: string,
  skills: OperatorSnapshot["skills"],
): SlashEntry[] {
  if (!/^\/[^\s]*$/.test(text)) return [];
  const query = text.slice(1).toLowerCase();
  return [
    ...Object.entries(commands).map(
      ([slug, description]): SlashEntry => ({
        slug,
        description,
        kind: "command",
      }),
    ),
    ...skills
      .filter(
        (skill) =>
          !Object.hasOwn(commands, skill.slug) &&
          !Object.hasOwn(COMMAND_ALIASES, skill.slug),
      )
      .map((skill): SlashEntry => ({ ...skill, kind: "skill" })),
  ]
    .filter((entry) =>
      `${entry.slug} ${entry.description}`.toLowerCase().includes(query),
    )
    .sort(
      (left, right) =>
        Number(right.slug.startsWith(query)) -
        Number(left.slug.startsWith(query)),
    );
}

export function commandRange(
  text: string,
  skills: OperatorSnapshot["skills"],
): { start: number; end: number } | undefined {
  const match = /^(\s*)\/([^\s]+)/.exec(text);
  if (!match) return;
  const name = match[2].toLowerCase();
  const canonical = COMMAND_ALIASES[name] ?? name;
  if (
    !Object.hasOwn(commands, canonical) &&
    !skills.some((skill) => skill.slug === canonical)
  )
    return;
  return { start: match[1].length, end: match[0].length };
}

import type { AutocompleteOption } from "../shared/prompt-input";
import type { OperatorSessionState } from "../../../core/operator";
import type { SkillsRegistry } from "../../../core/skills/registry";
import { BASE_SYSTEM_PROMPT } from "../../../core/agents/offSecAgent/prompt";

// ---------------------------------------------------------------------------
// Autocomplete option filtering for operator mode
// ---------------------------------------------------------------------------

export function filterOperatorAutocomplete(
  allOptions: AutocompleteOption[],
  skillSlugs: Set<string>,
): AutocompleteOption[] {
  const allowedCommands = new Set([
    "/models",
    "/auth",
    "/themes",
    "/new",
    "/operator",
    "/pentest",
    "/skills",
  ]);
  return allOptions
    .filter(
      (opt) => allowedCommands.has(opt.value) || skillSlugs.has(opt.value),
    )
    .map((opt) =>
      skillSlugs.has(opt.value)
        ? { value: opt.value, label: opt.label }
        : opt,
    );
}

// ---------------------------------------------------------------------------
// Submit gating
// ---------------------------------------------------------------------------

export type DashboardStatus = "idle" | "running" | "waiting" | "done";

export interface SubmitResult {
  action: "run" | "blocked" | "empty";
  prompt?: string;
  denyPending: boolean;
}

export function resolveSubmit(
  value: string,
  status: DashboardStatus,
  hasPendingApprovals: boolean,
): SubmitResult {
  const trimmed = value.trim();
  if (!trimmed) return { action: "empty", denyPending: false };
  if (status === "running")
    return { action: "blocked", denyPending: hasPendingApprovals };
  return { action: "run", prompt: trimmed, denyPending: hasPendingApprovals };
}

// ---------------------------------------------------------------------------
// Command routing
// ---------------------------------------------------------------------------

export type CommandAction =
  | { type: "show-models" }
  | { type: "run-skill"; slug: string; autopilot: boolean }
  | { type: "execute-command"; command: string };

export function routeCommand(
  command: string,
  resolveSkill: (cmd: string) => string | null,
): CommandAction {
  const commandLower = command.trim().replace(/^\/+/, "").toLowerCase();

  if (commandLower === "models" || commandLower === "model") {
    return { type: "show-models" };
  }

  const autopilot = command.includes("--autopilot");
  const cleanedCommand = command.replace(/\s*--autopilot\s*/g, "").trim();

  if (resolveSkill(cleanedCommand)) {
    // Reuse commandLower but take only the first word (slug without args)
    const slug = commandLower.split(/\s+/)[0] ?? commandLower;
    return { type: "run-skill", slug, autopilot };
  }

  return { type: "execute-command", command };
}

// ---------------------------------------------------------------------------
// Keyboard shortcut routing
// ---------------------------------------------------------------------------

interface KeyInfo {
  name: string;
  ctrl?: boolean;
  shift?: boolean;
  meta?: boolean;
  super?: boolean;
  raw?: string;
}

export type KeyboardAction =
  | { type: "skip" }
  | { type: "ctrl-c-abort" }
  | { type: "ctrl-c-clear" }
  | { type: "escape" }
  | { type: "toggle-verbose" }
  | { type: "toggle-expanded-logs" }
  | { type: "toggle-approval" }
  | { type: "toggle-mode" }
  | { type: "approve" }
  | { type: "auto-approve" };

export function resolveKeyboardShortcut(
  key: KeyInfo,
  status: DashboardStatus,
  inputValue: string,
  hasPendingApprovals: boolean,
  dialogOpen: boolean,
): KeyboardAction {
  if (dialogOpen) return { type: "skip" };

  // Terminal-native copy (Cmd+C / Super+C) passes through
  if ((key.meta || key.super) && key.name === "c") return { type: "skip" };

  // Ctrl+C
  if (key.ctrl && key.name === "c") {
    if (status === "running" || status === "waiting")
      return { type: "ctrl-c-abort" };
    if (inputValue.trim()) return { type: "ctrl-c-clear" };
    return { type: "skip" };
  }

  // Escape
  if (key.name === "escape" && status !== "running" && status !== "waiting") {
    return { type: "escape" };
  }

  // Ctrl+V — toggle verbose
  if (key.ctrl && key.name === "v") return { type: "toggle-verbose" };

  // Ctrl+L — toggle expanded logs
  if (key.ctrl && key.name === "l") return { type: "toggle-expanded-logs" };

  // Option+Shift+Tab — toggle approval
  if (key.name === "tab" && key.shift && key.meta)
    return { type: "toggle-approval" };

  // Shift+Tab — toggle plan/default mode
  if (key.name === "tab" && key.shift) return { type: "toggle-mode" };

  // Y to approve
  if (
    status === "waiting" &&
    hasPendingApprovals &&
    (key.name === "y" || key.raw === "Y")
  ) {
    return { type: "approve" };
  }

  // A to auto-approve
  if (
    status === "waiting" &&
    hasPendingApprovals &&
    (key.name === "a" || key.raw === "A")
  ) {
    return { type: "auto-approve" };
  }

  return { type: "skip" };
}

// ---------------------------------------------------------------------------
// Two-stage abort logic
// ---------------------------------------------------------------------------

export type AbortAction = { type: "cancel-command" } | { type: "kill-agent" };

export function resolveAbortAction(
  commandCancelled: boolean,
  cancelCommand: () => boolean,
): AbortAction {
  if (!commandCancelled && cancelCommand()) {
    return { type: "cancel-command" };
  }
  return { type: "kill-agent" };
}

// ---------------------------------------------------------------------------
// System prompt builder
// ---------------------------------------------------------------------------

export function buildOperatorSystemPrompt(
  target: string | undefined,
  operatorState: OperatorSessionState,
  agentMode?: "default" | "plan",
  opts?: {
    skillsCatalog?: string;
    activeSkillInstructions?: Array<{ name: string; instructions: string }>;
  },
): string {
  const { skillsCatalog, activeSkillInstructions } = opts ?? {};
  const modeNote =
    agentMode === "plan"
      ? "\nAgent mode: PLAN — read-only tools only, no mutations allowed"
      : "";

  let prompt = `${BASE_SYSTEM_PROMPT}

# Operator Mode

You are operating in interactive operator mode. The human operator will guide your actions through directives.

Target: ${target || "unknown"}
Stage: ${operatorState.currentStage}
Command approval: ${operatorState.requireApproval ? "enabled — the operator will approve each tool call" : "disabled — tool calls execute automatically"}${modeNote}`;

  if (skillsCatalog) {
    prompt += `\n\n# Skills\n\n${skillsCatalog}`;
  }

  if (activeSkillInstructions?.length) {
    for (const skill of activeSkillInstructions) {
      prompt += `\n\n# Active Skill: ${skill.name}\n\n${skill.instructions}`;
    }
  }

  return prompt;
}

// ---------------------------------------------------------------------------
// Input focus resolution
// ---------------------------------------------------------------------------

export function resolveInputFocused(
  status: DashboardStatus,
  dialogStackLength: number,
  externalDialogOpen: boolean,
): boolean {
  return status !== "running" && dialogStackLength === 0 && !externalDialogOpen;
}

// ---------------------------------------------------------------------------
// Token usage accumulation
// ---------------------------------------------------------------------------

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export function accumulateTokenUsage(
  current: TokenUsage,
  stepInputTokens: number,
  stepOutputTokens: number,
): TokenUsage | null {
  if (stepInputTokens <= 0 && stepOutputTokens <= 0) return null;
  return {
    inputTokens: current.inputTokens + stepInputTokens,
    outputTokens: current.outputTokens + stepOutputTokens,
    totalTokens: current.totalTokens + stepInputTokens + stepOutputTokens,
  };
}

// ---------------------------------------------------------------------------
// Inline skill reference extraction
// ---------------------------------------------------------------------------

export interface InlineSkillResult {
  /** The prompt with /skill-slug references removed */
  prompt: string;
  /** Slugs that were found and activated */
  activatedSlugs: string[];
}

/**
 * Extract inline /skill-slug references from a prompt, activate them,
 * and return the cleaned prompt.
 *
 * Matches word-boundary `/slug` patterns (e.g. "scan this /vulnerability-analysis").
 * Only activates slugs that exist and are enabled in the registry.
 */
export function extractInlineSkills(
  prompt: string,
  registry: SkillsRegistry,
): InlineSkillResult {
  const activatedSlugs: string[] = [];

  // Match /slug patterns that aren't at the very start (those are handled as commands)
  // Pattern: whitespace or start-of-string followed by /word-chars
  const cleaned = prompt.replace(
    /(?<=\s)\/([a-z0-9][-a-z0-9]*)/gi,
    (_match, slug: string) => {
      const normalized = slug.toLowerCase();
      const entry = registry.get(normalized);
      if (entry?.enabled) {
        try {
          registry.activate(normalized);
          activatedSlugs.push(normalized);
        } catch {
          // Already active or other issue — still strip it
          if (registry.isActive(normalized)) {
            activatedSlugs.push(normalized);
          }
        }
        return ""; // Remove the /slug from the prompt
      }
      return _match; // Not a known skill, leave it
    },
  );

  return {
    prompt: cleaned.replace(/\s{2,}/g, " ").trim(),
    activatedSlugs,
  };
}
